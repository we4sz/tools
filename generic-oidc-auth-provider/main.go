package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/tools/auth-providers-common/pkg/env"
	"github.com/obot-platform/tools/auth-providers-common/pkg/state"
	"github.com/obot-platform/tools/generic-oidc-auth-provider/pkg/profile"
)

type Options struct {
	ClientID     string `env:"OBOT_OIDC_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret string `env:"OBOT_OIDC_AUTH_PROVIDER_CLIENT_SECRET"`
	// IssuerURL is the OIDC issuer (e.g. https://auth.example.com/realms/myrealm).
	// oauth2-proxy performs discovery against {IssuerURL}/.well-known/openid-configuration.
	IssuerURL string `env:"OBOT_OIDC_AUTH_PROVIDER_ISSUER_URL"`
	// Scopes requested at login. "openid" is required; email/profile recommended.
	Scopes string `env:"OBOT_OIDC_AUTH_PROVIDER_SCOPES" default:"openid email profile" optional:"true"`
	// Claim names — defaults match the OIDC spec / Keycloak conventions.
	EmailClaim  string `env:"OBOT_OIDC_AUTH_PROVIDER_EMAIL_CLAIM" default:"email" optional:"true"`
	GroupsClaim string `env:"OBOT_OIDC_AUTH_PROVIDER_GROUPS_CLAIM" default:"groups" optional:"true"`
	// AllowUnverifiedEmail lets users without email_verified=true sign in.
	// Many self-hosted IdPs (e.g. Keycloak) do not set email_verified by default.
	AllowUnverifiedEmail string `env:"OBOT_OIDC_AUTH_PROVIDER_ALLOW_UNVERIFIED_EMAIL" default:"true" optional:"true"`

	ObotServerURL            string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN    string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	AuthCookieSecret         string `usage:"Secret used to encrypt cookie" env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains         string `usage:"Email domains allowed for authentication" default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	AuthTokenRefreshDuration string `usage:"Duration to refresh auth token after" optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`
	LoggingEnabled           string `usage:"Enable oauth2-proxy logging" optional:"true" env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING"`
}

// groupsFromBearerToken decodes a JWT bearer token (signature NOT verified —
// the token was already validated by oauth2-proxy upstream) and extracts the
// named claim as a list of group names. Returns nil when the token is opaque
// (not a JWT) or the claim is absent, so the caller can fall back to userinfo.
func groupsFromBearerToken(authHeader, claim string) []string {
	tok := strings.TrimSpace(authHeader)
	for _, p := range []string{"Bearer ", "bearer "} {
		tok = strings.TrimPrefix(tok, p)
	}
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	arr, ok := claims[claim].([]any)
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

type idpGroup struct {
	Name      string     `json:"name"`
	Path      string     `json:"path"`
	SubGroups []idpGroup `json:"subGroups"`
}

// listIdPGroupsViaKeycloakAdmin enumerates realm groups through Keycloak's Admin
// API using the OIDC client's own service-account (client_credentials). This is
// how Obot's enterprise connectors populate the group picker; generic OIDC has
// no group-list endpoint, so we offer it for Keycloak when the client has a
// service account with `query-groups`/`view-users`. Returns an error (so the
// caller falls back to per-user groups) for non-Keycloak issuers or missing
// permissions. Group names are returned as IDs to match the token groups claim.
func listIdPGroupsViaKeycloakAdmin(ctx context.Context, issuer, clientID, clientSecret, search string) (state.GroupInfoList, error) {
	issuer = strings.TrimRight(issuer, "/")
	idx := strings.Index(issuer, "/realms/")
	if idx < 0 || clientSecret == "" {
		return nil, fmt.Errorf("not a keycloak issuer or no client secret")
	}
	base := issuer[:idx]
	realm := issuer[idx+len("/realms/"):]
	if i := strings.IndexByte(realm, '/'); i >= 0 {
		realm = realm[:i]
	}

	// client_credentials token from the OIDC client's service account
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {clientSecret}}
	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second}
	tokResp, err := client.Do(tokReq)
	if err != nil {
		return nil, err
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client_credentials token request returned %d", tokResp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(tokResp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("no service-account token")
	}

	groupsURL := fmt.Sprintf("%s/admin/realms/%s/groups?briefRepresentation=true&max=1000", base, realm)
	if search != "" {
		groupsURL += "&search=" + url.QueryEscape(search)
	}
	gReq, err := http.NewRequestWithContext(ctx, http.MethodGet, groupsURL, nil)
	if err != nil {
		return nil, err
	}
	gReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	gResp, err := client.Do(gReq)
	if err != nil {
		return nil, err
	}
	defer gResp.Body.Close()
	if gResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin groups query returned %d", gResp.StatusCode)
	}
	var roots []idpGroup
	if err = json.NewDecoder(gResp.Body).Decode(&roots); err != nil {
		return nil, err
	}

	out := state.GroupInfoList{}
	var walk func([]idpGroup)
	walk = func(gs []idpGroup) {
		for _, g := range gs {
			// ID = leaf name to match the token's groups claim (full.path=false)
			out = append(out, state.GroupInfo{ID: g.Name, Name: g.Name})
			walk(g.SubGroups)
		}
	}
	walk(roots)
	return out, nil
}

func main() {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to load options: %v\n", err)
		os.Exit(1)
	}

	if opts.IssuerURL == "" {
		fmt.Printf("ERROR: generic-oidc-auth-provider: OBOT_OIDC_AUTH_PROVIDER_ISSUER_URL is required\n")
		os.Exit(1)
	}

	refreshDuration, err := time.ParseDuration(opts.AuthTokenRefreshDuration)
	if err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to parse token refresh duration: %v\n", err)
		os.Exit(1)
	}

	if refreshDuration < 0 {
		fmt.Printf("ERROR: generic-oidc-auth-provider: token refresh duration must be greater than 0\n")
		os.Exit(1)
	}

	cookieSecret, err := base64.StdEncoding.DecodeString(opts.AuthCookieSecret)
	if err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to decode cookie secret: %v\n", err)
		os.Exit(1)
	}

	legacyOpts := options.NewLegacyOptions()
	legacyOpts.LegacyProvider.ProviderType = "oidc"
	legacyOpts.LegacyProvider.ProviderName = "oidc"
	legacyOpts.LegacyProvider.ClientID = opts.ClientID
	legacyOpts.LegacyProvider.ClientSecret = opts.ClientSecret
	legacyOpts.LegacyProvider.OIDCIssuerURL = opts.IssuerURL
	legacyOpts.LegacyProvider.Scope = opts.Scopes
	legacyOpts.LegacyProvider.OIDCEmailClaim = opts.EmailClaim
	legacyOpts.LegacyProvider.OIDCGroupsClaim = opts.GroupsClaim
	legacyOpts.LegacyProvider.InsecureOIDCAllowUnverifiedEmail = strings.EqualFold(opts.AllowUnverifiedEmail, "true")

	oauthProxyOpts, err := legacyOpts.ToOptions()
	if err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to convert legacy options to new options: %v\n", err)
		os.Exit(1)
	}

	oauthProxyOpts.Server.BindAddress = ""
	oauthProxyOpts.MetricsServer.BindAddress = ""
	if opts.PostgresConnectionDSN != "" {
		oauthProxyOpts.Session.Type = options.PostgresSessionStoreType
		oauthProxyOpts.Session.Postgres.ConnectionDSN = opts.PostgresConnectionDSN
		oauthProxyOpts.Session.Postgres.TableNamePrefix = "oidc_"
	}
	oauthProxyOpts.Cookie.Refresh = refreshDuration
	oauthProxyOpts.Cookie.Name = "obot_access_token"
	oauthProxyOpts.Cookie.Secret = string(bytes.TrimSpace(cookieSecret))
	oauthProxyOpts.Cookie.Secure = strings.HasPrefix(opts.ObotServerURL, "https://")
	oauthProxyOpts.Cookie.CSRFExpire = 30 * time.Minute
	oauthProxyOpts.Templates.Path = os.Getenv("GPTSCRIPT_TOOL_DIR") + "/../auth-providers-common/templates"
	oauthProxyOpts.RawRedirectURL = opts.ObotServerURL + "/"
	if opts.AuthEmailDomains != "" {
		emailDomains := strings.Split(opts.AuthEmailDomains, ",")
		for i := range emailDomains {
			emailDomains[i] = strings.TrimSpace(emailDomains[i])
		}
		oauthProxyOpts.EmailDomains = emailDomains
	}

	loggingEnabled := strings.EqualFold(opts.LoggingEnabled, "true")
	oauthProxyOpts.Logging.RequestEnabled = loggingEnabled
	oauthProxyOpts.Logging.AuthEnabled = loggingEnabled
	oauthProxyOpts.Logging.StandardEnabled = loggingEnabled

	if err = validation.Validate(oauthProxyOpts); err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to validate options: %v\n", err)
		os.Exit(1)
	}

	oauthProxy, err := oauth2proxy.NewOAuthProxy(oauthProxyOpts, oauth2proxy.NewValidator(oauthProxyOpts.EmailDomains, oauthProxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to create oauth2 proxy: %v\n", err)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	issuerURL := strings.TrimRight(opts.IssuerURL, "/")

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("http://127.0.0.1:%s", port)))
	})
	mux.HandleFunc("/obot-get-state", state.ObotGetState(oauthProxy))
	mux.HandleFunc("/obot-get-user-info", func(w http.ResponseWriter, r *http.Request) {
		userInfo, err := profile.FetchOIDCProfile(r.Context(), issuerURL, r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to fetch user info: %v", err), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(userInfo)
	})
	mux.HandleFunc("/obot-list-user-auth-groups", func(w http.ResponseWriter, r *http.Request) {
		// Return the caller's groups so Obot can surface them for group-scoped
		// registries and group role assignments. Generic OIDC has no "list all
		// groups" endpoint, so this reports the authenticated user's own groups.
		//
		// Prefer decoding the groups claim straight from the (JWT) access token:
		// it needs no network call and keeps working even if the access token is
		// near/just expired (avoids spurious userinfo 401s). Fall back to the
		// userinfo endpoint for providers that issue opaque access tokens.
		// Preferred: enumerate realm groups via the IdP admin API (Keycloak) so
		// Obot can populate the group picker for group-scoped registries/roles.
		if groups, err := listIdPGroupsViaKeycloakAdmin(r.Context(), issuerURL, opts.ClientID, opts.ClientSecret, r.URL.Query().Get("name")); err == nil {
			json.NewEncoder(w).Encode(groups)
			return
		}
		// Fallback: the caller's own groups from their token (JWT claim, then userinfo).
		groupNames := groupsFromBearerToken(r.Header.Get("Authorization"), opts.GroupsClaim)
		if groupNames == nil {
			if userInfo, err := profile.FetchOIDCProfile(r.Context(), issuerURL, r.Header.Get("Authorization")); err == nil {
				groupNames = userInfo.Groups
			}
		}
		groups := make(state.GroupInfoList, 0, len(groupNames))
		for _, g := range groupNames {
			groups = append(groups, state.GroupInfo{ID: g, Name: g})
		}
		json.NewEncoder(w).Encode(groups)
	})
	mux.HandleFunc("/", oauthProxy.ServeHTTP)

	fmt.Printf("listening on 127.0.0.1:%s\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("ERROR: generic-oidc-auth-provider: failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}
