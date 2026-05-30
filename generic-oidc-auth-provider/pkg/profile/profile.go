package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// OIDCProfile is the normalized user info returned to Obot. Field names mirror
// the Google auth provider (id/email/verified_email/name/picture) so Obot's
// server can consume them uniformly, with OIDC-standard extras added.
type OIDCProfile struct {
	ID                string   `json:"id"`
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	VerifiedEmail     bool     `json:"verified_email"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	PreferredUsername string   `json:"preferred_username"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups,omitempty"`
}

type discoveryDoc struct {
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

var (
	discoveryCache = map[string]discoveryDoc{}
	discoveryMu    sync.Mutex
)

func discover(ctx context.Context, issuer string) (discoveryDoc, error) {
	discoveryMu.Lock()
	if d, ok := discoveryCache[issuer]; ok {
		discoveryMu.Unlock()
		return d, nil
	}
	discoveryMu.Unlock()

	url := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return discoveryDoc{}, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return discoveryDoc{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return discoveryDoc{}, fmt.Errorf("discovery at %s returned %d: %s", url, resp.StatusCode, body)
	}
	var d discoveryDoc
	if err = json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return discoveryDoc{}, err
	}
	if d.UserinfoEndpoint == "" {
		return discoveryDoc{}, fmt.Errorf("discovery doc at %s has no userinfo_endpoint", url)
	}

	discoveryMu.Lock()
	discoveryCache[issuer] = d
	discoveryMu.Unlock()
	return d, nil
}

// rawUserInfo captures the standard OIDC userinfo claims plus the common
// non-standard "groups" claim. email_verified can be a bool or a string
// depending on the IdP, so it is decoded leniently.
type rawUserInfo struct {
	Sub               string          `json:"sub"`
	Email             string          `json:"email"`
	EmailVerified     json.RawMessage `json:"email_verified"`
	Name              string          `json:"name"`
	GivenName         string          `json:"given_name"`
	FamilyName        string          `json:"family_name"`
	PreferredUsername string          `json:"preferred_username"`
	Picture           string          `json:"picture"`
	Groups            []string        `json:"groups"`
}

// FetchOIDCProfile discovers the issuer's userinfo endpoint and fetches the
// caller's claims using the provided Authorization header value.
func FetchOIDCProfile(ctx context.Context, issuer, authorization string) (*OIDCProfile, error) {
	doc, err := discover(ctx, issuer)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo at %s returned %d: %s", doc.UserinfoEndpoint, resp.StatusCode, body)
	}

	var raw rawUserInfo
	if err = json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	return &OIDCProfile{
		ID:                raw.Sub,
		Sub:               raw.Sub,
		Email:             raw.Email,
		VerifiedEmail:     parseVerified(raw.EmailVerified),
		Name:              raw.Name,
		GivenName:         raw.GivenName,
		FamilyName:        raw.FamilyName,
		PreferredUsername: raw.PreferredUsername,
		Picture:           raw.Picture,
		Groups:            raw.Groups,
	}, nil
}

func parseVerified(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "true"
	}
	return false
}
