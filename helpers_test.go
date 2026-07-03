// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/go-ruby-jwt/jwt"
)

// fixedNow is the deterministic clock the tests pin nowFunc to.
const fixedNow int64 = 1700000000

// pinClock sets nowFunc to a fixed instant for the duration of a test.
func pinClock(t *testing.T) {
	t.Helper()
	orig := nowFunc
	nowFunc = func() time.Time { return time.Unix(fixedNow, 0) }
	t.Cleanup(func() { nowFunc = orig })
}

// test keys — generated once and shared across the suite.
var (
	testRSA *rsa.PrivateKey
	testEC  *ecdsa.PrivateKey
)

func init() {
	var err error
	if testRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if testEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}
}

// rsaJWKS builds a single-key JWKS JSON for the test RSA public key under kid.
func rsaJWKS(t *testing.T, kid string) string {
	t.Helper()
	jk, err := jwt.NewJWK(&testRSA.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":%q,"n":%q,"e":%q}]}`,
		kid, jk.N, jk.E)
}

// ecJWKS builds a single-key JWKS JSON for the test EC public key under kid.
func ecJWKS(t *testing.T, kid string) string {
	t.Helper()
	jk, err := jwt.NewJWK(&testEC.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	return fmt.Sprintf(`{"keys":[{"kty":"EC","use":"sig","alg":"ES256","kid":%q,"crv":"P-256","x":%q,"y":%q}]}`,
		kid, jk.X, jk.Y)
}

// signRS signs claims as an RS256 ID token with the given header kid.
func signRS(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Encode(claims, testRSA, "RS256", map[string]any{"kid": kid})
	if err != nil {
		t.Fatalf("Encode RS256: %v", err)
	}
	return tok
}

// signES signs claims as an ES256 ID token with the given header kid.
func signES(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Encode(claims, testEC, "ES256", map[string]any{"kid": kid})
	if err != nil {
		t.Fatalf("Encode ES256: %v", err)
	}
	return tok
}

// signHS signs claims as an HS256 ID token with the given secret.
func signHS(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Encode(claims, secret, "HS256", nil)
	if err != nil {
		t.Fatalf("Encode HS256: %v", err)
	}
	return tok
}

// validClaims returns a fresh, fully-valid ID-token claim set for issuer/aud.
func validClaims(issuer, aud, nonce string) map[string]any {
	return map[string]any{
		"iss":   issuer,
		"sub":   "subject-123",
		"aud":   aud,
		"exp":   fixedNow + 3600,
		"iat":   fixedNow - 30,
		"nonce": nonce,
	}
}

// mockDoer routes requests by exact URL to a canned response, recording the last
// request seen (for assertions on headers/body).
type mockDoer struct {
	routes map[string]*HTTPResponse
	errs   map[string]error
	last   *HTTPRequest
	byURL  map[string]*HTTPRequest
	calls  int
}

func newMockDoer() *mockDoer {
	return &mockDoer{routes: map[string]*HTTPResponse{}, errs: map[string]error{}, byURL: map[string]*HTTPRequest{}}
}

// on registers a JSON 200 response for a URL.
func (m *mockDoer) on(url, body string) *mockDoer {
	m.routes[url] = &HTTPResponse{Status: 200, Header: map[string]string{"Content-Type": "application/json"}, Body: body}
	return m
}

// onResp registers an arbitrary response for a URL.
func (m *mockDoer) onResp(url string, resp *HTTPResponse) *mockDoer {
	m.routes[url] = resp
	return m
}

// onErr registers a transport error for a URL.
func (m *mockDoer) onErr(url string, err error) *mockDoer {
	m.errs[url] = err
	return m
}

func (m *mockDoer) Do(req *HTTPRequest) (*HTTPResponse, error) {
	m.last = req
	m.byURL[req.URL] = req
	m.calls++
	if err, ok := m.errs[req.URL]; ok {
		return nil, err
	}
	if resp, ok := m.routes[req.URL]; ok {
		return resp, nil
	}
	return &HTTPResponse{Status: 404, Header: map[string]string{}, Body: "not found"}, nil
}
