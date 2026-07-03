// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"fmt"
	"testing"
)

// discoveryJSON builds a discovery document for issuer with all endpoints.
func discoveryJSON(issuer string) string {
	return fmt.Sprintf(`{
		"issuer":%q,
		"authorization_endpoint":"%s/auth",
		"token_endpoint":"%s/token",
		"userinfo_endpoint":"%s/userinfo",
		"jwks_uri":"%s/jwks",
		"scopes_supported":["openid","email"],
		"id_token_signing_alg_values_supported":["RS256"]
	}`, issuer, issuer, issuer, issuer, issuer)
}

func TestDiscoveryURL(t *testing.T) {
	want := "https://x/.well-known/openid-configuration"
	if got := discoveryURL("https://x"); got != want {
		t.Errorf("no-slash: %q", got)
	}
	if got := discoveryURL("https://x/"); got != want {
		t.Errorf("trailing-slash: %q", got)
	}
}

func TestParseProviderMetadata_Valid(t *testing.T) {
	pm, err := ParseProviderMetadata([]byte(discoveryJSON(testIssuer)))
	if err != nil {
		t.Fatal(err)
	}
	if pm.Issuer != testIssuer || pm.JWKSURI != testIssuer+"/jwks" {
		t.Errorf("bad metadata %+v", pm)
	}
	if len(pm.ScopesSupported) != 2 || pm.Raw["issuer"] != testIssuer {
		t.Errorf("raw/scopes not populated: %+v", pm)
	}
}

func TestParseProviderMetadata_MalformedJSON(t *testing.T) {
	if _, err := ParseProviderMetadata([]byte("[1,2,3]")); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("want ErrDiscovery, got %v", err)
	}
}

func TestParseProviderMetadata_MissingFields(t *testing.T) {
	cases := map[string]string{
		"no-issuer": `{"authorization_endpoint":"a","token_endpoint":"t","jwks_uri":"j"}`,
		"no-authz":  `{"issuer":"i","token_endpoint":"t","jwks_uri":"j"}`,
		"no-token":  `{"issuer":"i","authorization_endpoint":"a","jwks_uri":"j"}`,
		"no-jwks":   `{"issuer":"i","authorization_endpoint":"a","token_endpoint":"t"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProviderMetadata([]byte(body)); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("want ErrDiscovery, got %v", err)
			}
		})
	}
}

func TestDiscover(t *testing.T) {
	url := discoveryURL(testIssuer)

	t.Run("success", func(t *testing.T) {
		d := newMockDoer().on(url, discoveryJSON(testIssuer))
		pm, err := Discover(d, testIssuer)
		if err != nil || pm.Issuer != testIssuer {
			t.Fatalf("discover: %v %+v", err, pm)
		}
	})
	t.Run("transport-error", func(t *testing.T) {
		d := newMockDoer().onErr(url, errors.New("net down"))
		if _, err := Discover(d, testIssuer); !errors.Is(err, ErrDiscovery) || !errors.Is(err, ErrHTTP) {
			t.Fatalf("want ErrDiscovery+ErrHTTP, got %v", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		d := newMockDoer().onResp(url, &HTTPResponse{Status: 404, Header: map[string]string{}, Body: ""})
		if _, err := Discover(d, testIssuer); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("want ErrDiscovery, got %v", err)
		}
	})
	t.Run("bad-body", func(t *testing.T) {
		d := newMockDoer().on(url, "{bad")
		if _, err := Discover(d, testIssuer); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("want ErrDiscovery, got %v", err)
		}
	})
	t.Run("issuer-mismatch", func(t *testing.T) {
		d := newMockDoer().on(url, discoveryJSON("https://someone-else"))
		if _, err := Discover(d, testIssuer); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("want ErrDiscovery (mismatch), got %v", err)
		}
	})
}
