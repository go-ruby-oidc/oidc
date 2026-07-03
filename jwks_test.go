// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-ruby-jwt/jwt"
)

// rsaNE returns the base64url modulus/exponent of the test RSA public key.
func rsaNE(t *testing.T) (string, string) {
	t.Helper()
	jk, err := jwt.NewJWK(&testRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return jk.N, jk.E
}

func TestParseJWKS_RSAandEC(t *testing.T) {
	ks := mustKeySet(t, rsaJWKS(t, "k1"))
	if len(ks.Keys()) != 1 {
		t.Fatalf("keys=%d", len(ks.Keys()))
	}
	k := ks.Find("k1")
	if k == nil || k.PublicKey() == nil || k.Kty != "RSA" {
		t.Fatalf("bad key %+v", k)
	}
	if ks.Find("nope") != nil {
		t.Error("Find(nope) not nil")
	}
	ec := mustKeySet(t, ecJWKS(t, "e1"))
	if ec.Find("e1").Kty != "EC" {
		t.Error("EC kty")
	}
}

func TestParseJWKS_SkipsUnknownKty(t *testing.T) {
	n, e := rsaNE(t)
	body := fmt.Sprintf(`{"keys":[{"kty":"oct","kid":"sym","k":"AAAA"},{"kty":"RSA","kid":"k1","n":%q,"e":%q}]}`, n, e)
	ks := mustKeySet(t, body)
	if len(ks.Keys()) != 1 || ks.Find("k1") == nil {
		t.Fatalf("unknown kty not skipped: %d keys", len(ks.Keys()))
	}
}

func TestParseJWKS_MalformedJSON(t *testing.T) {
	if _, err := ParseJWKS([]byte("{not json")); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
}

func TestParseJWKS_KeyBuildErrors(t *testing.T) {
	_, e := rsaNE(t)
	cases := []struct{ name, body string }{
		{"bad-n", fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"x","n":"@@@","e":%q}]}`, e)},
		{"bad-e", `{"keys":[{"kty":"RSA","kid":"x","n":"AQAB","e":"@@@"}]}`},
		{"empty-n", `{"keys":[{"kty":"RSA","kid":"x","n":"","e":"AQAB"}]}`},
		{"zero-e", `{"keys":[{"kty":"RSA","kid":"x","n":"AQAB","e":"AA"}]}`},
		{"huge-e", `{"keys":[{"kty":"RSA","kid":"x","n":"AQAB","e":"__________8"}]}`},
		{"bad-crv", `{"keys":[{"kty":"EC","kid":"x","crv":"P-999","x":"AQAB","y":"AQAB"}]}`},
		{"bad-ec-x", `{"keys":[{"kty":"EC","kid":"x","crv":"P-256","x":"@@@","y":"AQAB"}]}`},
		{"bad-ec-y", `{"keys":[{"kty":"EC","kid":"x","crv":"P-256","x":"AQAB","y":"@@@"}]}`},
		{"empty-ec-x", `{"keys":[{"kty":"EC","kid":"x","crv":"P-256","x":"","y":"AQAB"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJWKS([]byte(tc.body)); !errors.Is(err, ErrJWKS) {
				t.Fatalf("want ErrJWKS, got %v", err)
			}
		})
	}
}

func TestCurveByName(t *testing.T) {
	for _, name := range []string{"P-256", "P-384", "P-521"} {
		if _, err := curveByName(name); err != nil {
			t.Errorf("curveByName(%q): %v", name, err)
		}
	}
	if _, err := curveByName("P-000"); err == nil {
		t.Error("want error for unknown curve")
	}
}

func TestB64URL(t *testing.T) {
	if b, err := b64url("YWJj"); err != nil || string(b) != "abc" {
		t.Errorf("raw: %q %v", b, err)
	}
	// A padded (standard-url) encoding falls back to the padded decoder.
	if b, err := b64url(base64.URLEncoding.EncodeToString([]byte("hi"))); err != nil || string(b) != "hi" {
		t.Errorf("padded: %q %v", b, err)
	}
	if _, err := b64url("@@@"); err == nil {
		t.Error("want error for invalid base64")
	}
}

func TestKeySetSelect(t *testing.T) {
	n, e := rsaNE(t)
	// kid found / not found.
	ks := mustKeySet(t, rsaJWKS(t, "k1"))
	if _, err := ks.Select("k1", "RS256"); err != nil {
		t.Fatalf("select k1: %v", err)
	}
	if _, err := ks.Select("missing", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
	// no-kid, single candidate.
	if _, err := ks.Select("", "RS256"); err != nil {
		t.Fatalf("select no-kid single: %v", err)
	}
	// no-kid, ambiguous (two RSA sig keys).
	two := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"a","n":%q,"e":%q},{"kty":"RSA","kid":"b","n":%q,"e":%q}]}`, n, e, n, e)
	if _, err := mustKeySet(t, two).Select("", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ambiguous ErrJWKS, got %v", err)
	}
	// no-kid, an enc key is filtered, leaving one sig candidate.
	mixed := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"enc","use":"enc","n":%q,"e":%q},{"kty":"RSA","kid":"sig","use":"sig","n":%q,"e":%q}]}`, n, e, n, e)
	k, err := mustKeySet(t, mixed).Select("", "RS256")
	if err != nil || k.Kid != "sig" {
		t.Fatalf("mixed select: %v key=%+v", err, k)
	}
	// no-kid, an EC key is filtered by alg/kty, leaving the sole RSA candidate.
	jkEC, err := jwt.NewJWK(&testEC.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mixedKty := fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"ec","crv":"P-256","x":%q,"y":%q},{"kty":"RSA","kid":"rsa","n":%q,"e":%q}]}`,
		jkEC.X, jkEC.Y, n, e)
	k2, err := mustKeySet(t, mixedKty).Select("", "RS256")
	if err != nil || k2.Kid != "rsa" {
		t.Fatalf("mixed-kty select: %v key=%+v", err, k2)
	}
}

func TestFetchJWKS(t *testing.T) {
	uri := "https://p/jwks"
	// success
	d := newMockDoer().on(uri, rsaJWKS(t, "k1"))
	if _, err := FetchJWKS(d, uri); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// transport error
	de := newMockDoer().onErr(uri, errors.New("boom"))
	if _, err := FetchJWKS(de, uri); !errors.Is(err, ErrJWKS) || !errors.Is(err, ErrHTTP) {
		t.Fatalf("want ErrJWKS+ErrHTTP, got %v", err)
	}
	// non-200
	d5 := newMockDoer().onResp(uri, &HTTPResponse{Status: 500, Header: map[string]string{}, Body: ""})
	if _, err := FetchJWKS(d5, uri); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS (status), got %v", err)
	}
}

func TestJWKSCache_GetCachesAndExpires(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	d := newMockDoer().on(uri, rsaJWKS(t, "k1"))
	c := NewJWKSCache(d, uri, time.Minute)

	if _, err := c.Get(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(); err != nil { // served from cache
		t.Fatal(err)
	}
	if d.calls != 1 {
		t.Fatalf("expected 1 fetch, got %d", d.calls)
	}
	// Advance beyond the TTL: a refetch happens.
	nowFunc = func() time.Time { return time.Unix(fixedNow+120, 0) }
	if _, err := c.Get(); err != nil {
		t.Fatal(err)
	}
	if d.calls != 2 {
		t.Fatalf("expected refetch, got %d calls", d.calls)
	}
}

func TestJWKSCache_GetFetchError(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	c := NewJWKSCache(newMockDoer().onErr(uri, errors.New("down")), uri, 0)
	if _, err := c.Get(); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
}

func TestJWKSCache_SelectRotation(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	d := newMockDoer().on(uri, rsaJWKS(t, "k1"))
	c := NewJWKSCache(d, uri, 0) // never expires until a kid miss

	// First select fetches and finds k1.
	if _, err := c.Select("k1", "RS256"); err != nil {
		t.Fatal(err)
	}
	// Rotate the provider's keys to k2; a miss on cached set forces one refetch.
	d.on(uri, rsaJWKS(t, "k2"))
	if _, err := c.Select("k2", "RS256"); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if d.calls != 2 {
		t.Fatalf("expected 2 fetches, got %d", d.calls)
	}
	// A kid absent even after a fresh fetch returns the miss error.
	if _, err := c.Select("k9", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
}

func TestJWKSCache_SelectFreshMiss(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	// Empty cache: load fetches fresh; the requested kid is absent → return the
	// miss without a second fetch.
	d := newMockDoer().on(uri, rsaJWKS(t, "k1"))
	c := NewJWKSCache(d, uri, time.Minute)
	if _, err := c.Select("absent", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
	if d.calls != 1 {
		t.Fatalf("expected single fetch on fresh miss, got %d", d.calls)
	}
}

func TestJWKSCache_SelectLoadError(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	c := NewJWKSCache(newMockDoer().onErr(uri, errors.New("x")), uri, 0)
	if _, err := c.Select("k1", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS, got %v", err)
	}
}

func TestJWKSCache_SelectRefetchError(t *testing.T) {
	pinClock(t)
	uri := "https://p/jwks"
	d := newMockDoer().on(uri, rsaJWKS(t, "k1"))
	c := NewJWKSCache(d, uri, 0)
	if _, err := c.Select("k1", "RS256"); err != nil { // populate cache
		t.Fatal(err)
	}
	// Now make the refetch (triggered by a cached miss) fail.
	d.onErr(uri, errors.New("refetch-down"))
	if _, err := c.Select("k2", "RS256"); !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrJWKS on refetch, got %v", err)
	}
}
