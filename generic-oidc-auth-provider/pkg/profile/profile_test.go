package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchOIDCProfile(t *testing.T) {
	// Mock IdP: serves discovery + userinfo. The userinfo response includes a
	// string email_verified to exercise the lenient parser, plus groups.
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":            base,
			"userinfo_endpoint": base + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			http.Error(w, "unexpected auth: "+got, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"sub":"abc-123","email":"jane@example.com","email_verified":"true",`+
			`"name":"Jane Doe","preferred_username":"jane","groups":["devs","admins"]}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	base = server.URL

	p, err := FetchOIDCProfile(context.Background(), server.URL, "Bearer tok")
	if err != nil {
		t.Fatalf("FetchOIDCProfile returned error: %v", err)
	}
	if p.ID != "abc-123" || p.Sub != "abc-123" {
		t.Errorf("unexpected id/sub: %q/%q", p.ID, p.Sub)
	}
	if p.Email != "jane@example.com" {
		t.Errorf("unexpected email: %q", p.Email)
	}
	if !p.VerifiedEmail {
		t.Errorf("expected verified_email true from string \"true\"")
	}
	if p.PreferredUsername != "jane" {
		t.Errorf("unexpected preferred_username: %q", p.PreferredUsername)
	}
	if len(p.Groups) != 2 || p.Groups[0] != "devs" {
		t.Errorf("unexpected groups: %v", p.Groups)
	}
}

func TestParseVerified(t *testing.T) {
	cases := map[string]bool{`true`: true, `false`: false, `"true"`: true, `"false"`: false, ``: false}
	for in, want := range cases {
		if got := parseVerified(json.RawMessage(in)); got != want {
			t.Errorf("parseVerified(%q) = %v, want %v", in, got, want)
		}
	}
}
