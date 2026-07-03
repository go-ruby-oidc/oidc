// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/go-ruby-oauth2/oauth2"
)

// testMetadata returns provider metadata pointing every endpoint at testIssuer.
func testMetadata() *ProviderMetadata {
	return &ProviderMetadata{
		Issuer:                testIssuer,
		AuthorizationEndpoint: testIssuer + "/auth",
		TokenEndpoint:         testIssuer + "/token",
		UserinfoEndpoint:      testIssuer + "/userinfo",
		JWKSURI:               testIssuer + "/jwks",
	}
}

func TestNewClient_Errors(t *testing.T) {
	if _, err := NewClient(Config{Doer: newMockDoer()}); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil metadata: want ErrConfig, got %v", err)
	}
	if _, err := NewClient(Config{Metadata: testMetadata()}); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil doer: want ErrConfig, got %v", err)
	}
	if _, err := NewClient(Config{Metadata: testMetadata(), Doer: newMockDoer()}); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

func TestDiscoverClient(t *testing.T) {
	url := discoveryURL(testIssuer)
	t.Run("nil-doer", func(t *testing.T) {
		if _, err := DiscoverClient(Config{}, testIssuer); !errors.Is(err, ErrConfig) {
			t.Fatalf("want ErrConfig, got %v", err)
		}
	})
	t.Run("discover-error", func(t *testing.T) {
		d := newMockDoer().onResp(url, &HTTPResponse{Status: 500, Header: map[string]string{}, Body: ""})
		if _, err := DiscoverClient(Config{Doer: d}, testIssuer); !errors.Is(err, ErrDiscovery) {
			t.Fatalf("want ErrDiscovery, got %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		d := newMockDoer().on(url, discoveryJSON(testIssuer))
		c, err := DiscoverClient(Config{Doer: d, ClientID: testClient}, testIssuer)
		if err != nil || c == nil {
			t.Fatalf("discover client: %v", err)
		}
	})
}

func newTestClient(t *testing.T, d Doer) *Client {
	t.Helper()
	c, err := NewClient(Config{
		Metadata:     testMetadata(),
		ClientID:     testClient,
		ClientSecret: "sekret",
		RedirectURI:  "https://app/cb",
		Scopes:       []string{"email"},
		Doer:         d,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthCodeURL(t *testing.T) {
	c := newTestClient(t, newMockDoer())

	raw := c.AuthCodeURL(AuthParams{
		State:        "st8",
		Nonce:        "nOnce",
		CodeVerifier: "verifier-1234567890",
		Scopes:       []string{"profile"},
		Extra:        oauth2.Params{{Key: "prompt", Val: "consent"}},
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("scope") != "openid email profile" {
		t.Errorf("scope=%q", q.Get("scope"))
	}
	if q.Get("response_type") != "code" || q.Get("client_id") != testClient {
		t.Errorf("client defaults missing: %v", q)
	}
	if q.Get("state") != "st8" || q.Get("nonce") != "nOnce" {
		t.Errorf("state/nonce: %v", q)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("pkce method=%q", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") != oauth2.CodeChallenge("verifier-1234567890", oauth2.PKCES256) {
		t.Errorf("code_challenge=%q", q.Get("code_challenge"))
	}
	if q.Get("prompt") != "consent" {
		t.Errorf("extra prompt missing")
	}
	if q.Get("redirect_uri") != "https://app/cb" {
		t.Errorf("redirect_uri=%q", q.Get("redirect_uri"))
	}
}

func TestAuthCodeURL_NoPKCENoStateNonce(t *testing.T) {
	c := newTestClient(t, newMockDoer())
	raw := c.AuthCodeURL(AuthParams{})
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Has("code_challenge") || q.Has("state") || q.Has("nonce") {
		t.Errorf("unexpected optional params: %v", q)
	}
	if q.Get("scope") != "openid email" {
		t.Errorf("scope=%q", q.Get("scope"))
	}
}

func TestMergeScopes(t *testing.T) {
	if got := mergeScopes([]string{"email", "", "email"}, []string{"profile", "openid"}); got != "openid email profile" {
		t.Errorf("mergeScopes=%q", got)
	}
}

// tokenResponse builds a JSON token-endpoint body carrying an id_token.
func tokenResponseBody(idToken string) string {
	return `{"access_token":"access-xyz","token_type":"bearer","expires_in":3600,"id_token":"` + idToken + `"}`
}

func jsonResp(body string) *HTTPResponse {
	return &HTTPResponse{Status: 200, Header: map[string]string{"Content-Type": "application/json"}, Body: body}
}

func TestExchange_Success(t *testing.T) {
	pinClock(t)
	idToken := signRS(t, "k1", validClaims(testIssuer, testClient, "n1"))
	d := newMockDoer().
		on(testIssuer+"/jwks", rsaJWKS(t, "k1")).
		onResp(testIssuer+"/token", jsonResp(tokenResponseBody(idToken)))
	c := newTestClient(t, d)

	tokens, err := c.Exchange("the-code", "verifier-1234567890", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.Access.Token != "access-xyz" {
		t.Errorf("access token=%q", tokens.Access.Token)
	}
	if tokens.IDToken != idToken || tokens.Claims.Subject() != "subject-123" {
		t.Errorf("id token/claims wrong")
	}
	// The token request carried the PKCE verifier and the authorization code.
	tokReq := d.byURL[testIssuer+"/token"]
	if tokReq == nil || tokReq.Method != "POST" {
		t.Fatalf("no POST token request: %+v", tokReq)
	}
	if !strings.Contains(tokReq.Body, "code_verifier") || !strings.Contains(tokReq.Body, "grant_type") {
		t.Errorf("token body missing pkce/grant: %q", tokReq.Body)
	}
}

func TestExchange_TransportError(t *testing.T) {
	pinClock(t)
	d := newMockDoer().onErr(testIssuer+"/token", errors.New("net"))
	c := newTestClient(t, d)
	if _, err := c.Exchange("code", "", ""); !errors.Is(err, ErrHTTP) {
		t.Fatalf("want ErrHTTP, got %v", err)
	}
}

func TestExchange_TokenEndpointError(t *testing.T) {
	pinClock(t)
	d := newMockDoer().onResp(testIssuer+"/token", &HTTPResponse{
		Status: 400, Header: map[string]string{"Content-Type": "application/json"},
		Body: `{"error":"invalid_grant","error_description":"bad code"}`,
	})
	c := newTestClient(t, d)
	if _, err := c.Exchange("code", "", ""); !errors.Is(err, ErrToken) {
		t.Fatalf("want ErrToken, got %v", err)
	}
}

func TestExchange_NoIDToken(t *testing.T) {
	pinClock(t)
	d := newMockDoer().onResp(testIssuer+"/token",
		jsonResp(`{"access_token":"a","token_type":"bearer"}`))
	c := newTestClient(t, d)
	if _, err := c.Exchange("code", "", ""); !errors.Is(err, ErrNoIDToken) {
		t.Fatalf("want ErrNoIDToken, got %v", err)
	}
}

func TestExchange_IDTokenVerifyFails(t *testing.T) {
	pinClock(t)
	// id_token with the wrong issuer → verification fails.
	idToken := signRS(t, "k1", validClaims("https://wrong-issuer", testClient, ""))
	d := newMockDoer().
		on(testIssuer+"/jwks", rsaJWKS(t, "k1")).
		onResp(testIssuer+"/token", jsonResp(tokenResponseBody(idToken)))
	c := newTestClient(t, d)
	if _, err := c.Exchange("code", "", ""); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("want ErrInvalidIssuer, got %v", err)
	}
}

func TestClient_Verifier(t *testing.T) {
	c := newTestClient(t, newMockDoer())
	v := c.Verifier()
	if v.Issuer != testIssuer || v.ClientID != testClient || v.Keys == nil {
		t.Errorf("verifier not wired: %+v", v)
	}
	if string(v.HMACSecret) != "sekret" {
		t.Errorf("hmac secret=%q", v.HMACSecret)
	}
}

func TestClient_UserInfo(t *testing.T) {
	d := newMockDoer().on(testIssuer+"/userinfo", `{"sub":"subject-123"}`)
	c := newTestClient(t, d)
	u, err := c.UserInfo("access-xyz")
	if err != nil || u.Subject() != "subject-123" {
		t.Fatalf("userinfo: %v %+v", err, u)
	}
}
