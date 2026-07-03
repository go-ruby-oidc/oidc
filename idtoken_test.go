// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-ruby-jwt/jwt"
)

const (
	testIssuer = "https://issuer.example.com"
	testClient = "client-abc"
)

// mustKeySet parses a JWKS JSON into a KeySet or fails the test.
func mustKeySet(t *testing.T, body string) *KeySet {
	t.Helper()
	ks, err := ParseJWKS([]byte(body))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	return ks
}

// craft assembles a compact JWS from raw header/payload/signature strings.
func craft(header, payload, sig string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(header) + "." + enc(payload) + "." + enc(sig)
}

// rsVerifier returns a Verifier that trusts the test RSA key under kid "k1".
func rsVerifier(t *testing.T) *Verifier {
	return &Verifier{Issuer: testIssuer, ClientID: testClient, Keys: mustKeySet(t, rsaJWKS(t, "k1"))}
}

func TestVerify_ValidRS256(t *testing.T) {
	pinClock(t)
	tok := signRS(t, "k1", validClaims(testIssuer, testClient, "n0"))
	v := rsVerifier(t)
	v.Nonce = "n0"
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer() != testIssuer {
		t.Errorf("Issuer=%q", claims.Issuer())
	}
	if claims.Subject() != "subject-123" {
		t.Errorf("Subject=%q", claims.Subject())
	}
	if claims.Nonce() != "n0" {
		t.Errorf("Nonce=%q", claims.Nonce())
	}
	if got := claims.Audience(); len(got) != 1 || got[0] != testClient {
		t.Errorf("Audience=%v", got)
	}
	if claims.ExpiresAt() != fixedNow+3600 {
		t.Errorf("ExpiresAt=%d", claims.ExpiresAt())
	}
	if claims.IssuedAt() != fixedNow-30 {
		t.Errorf("IssuedAt=%d", claims.IssuedAt())
	}
	if v, ok := claims.String("sub"); !ok || v != "subject-123" {
		t.Errorf("String(sub)=%q,%v", v, ok)
	}
	if v, ok := claims.Get("aud"); !ok || v != testClient {
		t.Errorf("Get(aud)=%v,%v", v, ok)
	}
	if claims.Raw() == nil {
		t.Error("Raw nil")
	}
}

func TestVerify_ValidES256(t *testing.T) {
	pinClock(t)
	tok := signES(t, "e1", validClaims(testIssuer, testClient, ""))
	v := &Verifier{Issuer: testIssuer, ClientID: testClient, Keys: mustKeySet(t, ecJWKS(t, "e1"))}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("Verify ES256: %v", err)
	}
}

func TestVerify_ValidHS256(t *testing.T) {
	pinClock(t)
	tok := signHS(t, "topsecret", validClaims(testIssuer, testClient, ""))
	v := &Verifier{Issuer: testIssuer, ClientID: testClient, HMACSecret: []byte("topsecret")}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("Verify HS256: %v", err)
	}
}

func TestVerify_NoKidSingleKey(t *testing.T) {
	pinClock(t)
	// Sign with an empty kid; the sole matching key is selected by alg.
	tok, err := jwt.Encode(validClaims(testIssuer, testClient, ""), testRSA, "RS256", nil)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Issuer: testIssuer, ClientID: testClient, Keys: mustKeySet(t, rsaJWKS(t, "k1"))}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("Verify no-kid: %v", err)
	}
}

func TestVerify_RejectMalformedToken(t *testing.T) {
	pinClock(t)
	v := rsVerifier(t)
	if _, err := v.Verify("not-a-jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestVerify_RejectHeaderNotObject(t *testing.T) {
	pinClock(t)
	tok := craft(`"stringheader"`, `{}`, "")
	if _, err := rsVerifier(t).Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestVerify_RejectNoAlg(t *testing.T) {
	pinClock(t)
	tok := craft(`{"typ":"JWT"}`, `{}`, "sig")
	if _, err := rsVerifier(t).Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestVerify_RejectAlgNone(t *testing.T) {
	pinClock(t)
	tok, err := jwt.Encode(validClaims(testIssuer, testClient, ""), nil, "none", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rsVerifier(t).Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken (none), got %v", err)
	}
}

func TestVerify_RejectUnsupportedAlg(t *testing.T) {
	pinClock(t)
	tok := signES(t, "e1", validClaims(testIssuer, testClient, ""))
	v := &Verifier{Issuer: testIssuer, ClientID: testClient, Algorithms: []string{"RS256"},
		Keys: mustKeySet(t, ecJWKS(t, "e1"))}
	if _, err := v.Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken (alg), got %v", err)
	}
}

func TestVerify_HSWithoutSecret(t *testing.T) {
	pinClock(t)
	tok := signHS(t, "s", validClaims(testIssuer, testClient, ""))
	v := &Verifier{Issuer: testIssuer, ClientID: testClient}
	if _, err := v.Verify(tok); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestVerify_NoKeySource(t *testing.T) {
	pinClock(t)
	tok := signRS(t, "k1", validClaims(testIssuer, testClient, ""))
	v := &Verifier{Issuer: testIssuer, ClientID: testClient}
	if _, err := v.Verify(tok); !errors.Is(err, ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestVerify_KidNotFound(t *testing.T) {
	pinClock(t)
	tok := signRS(t, "other", validClaims(testIssuer, testClient, ""))
	v := rsVerifier(t) // knows only kid "k1"
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrInvalidToken) || !errors.Is(err, ErrJWKS) {
		t.Fatalf("want ErrInvalidToken+ErrJWKS, got %v", err)
	}
}

func TestVerify_SignatureMismatch(t *testing.T) {
	pinClock(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Encode(validClaims(testIssuer, testClient, ""), other, "RS256", map[string]any{"kid": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rsVerifier(t).Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken (sig), got %v", err)
	}
}

func TestVerify_PayloadNotObject(t *testing.T) {
	pinClock(t)
	tok, err := jwt.Encode("just-a-string", testRSA, "RS256", map[string]any{"kid": "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rsVerifier(t).Verify(tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken (payload), got %v", err)
	}
}

// TestVerify_ClaimRejections drives every OIDC claim rejection branch.
func TestVerify_ClaimRejections(t *testing.T) {
	pinClock(t)
	base := func() map[string]any { return validClaims(testIssuer, testClient, "") }

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		verifer func(*Verifier)
		want    error
	}{
		{"wrong-iss", func(c map[string]any) { c["iss"] = "https://evil" }, nil, ErrInvalidIssuer},
		{"missing-iss", func(c map[string]any) { delete(c, "iss") }, nil, ErrInvalidIssuer},
		{"missing-aud", func(c map[string]any) { delete(c, "aud") }, nil, ErrInvalidAudience},
		{"wrong-aud", func(c map[string]any) { c["aud"] = "someone-else" }, nil, ErrInvalidAudience},
		{"azp-wrong", func(c map[string]any) { c["azp"] = "not-client" }, nil, ErrInvalidAzp},
		{"multi-aud-no-azp", func(c map[string]any) { c["aud"] = []any{testClient, "second"} }, nil, ErrInvalidAzp},
		{"missing-exp", func(c map[string]any) { delete(c, "exp") }, nil, ErrExpired},
		{"expired", func(c map[string]any) { c["exp"] = fixedNow - 10 }, nil, ErrExpired},
		{"missing-iat", func(c map[string]any) { delete(c, "iat") }, nil, ErrInvalidIat},
		{"future-iat", func(c map[string]any) { c["iat"] = fixedNow + 10000 }, nil, ErrInvalidIat},
		{"future-nbf", func(c map[string]any) { c["nbf"] = fixedNow + 10000 }, nil, ErrNotYetValid},
		{"nonce-mismatch", func(c map[string]any) { c["nonce"] = "wrong" }, func(v *Verifier) { v.Nonce = "expected" }, ErrInvalidNonce},
		{"nonce-missing", func(c map[string]any) {}, func(v *Verifier) { v.Nonce = "expected" }, ErrInvalidNonce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			tok := signRS(t, "k1", c)
			v := rsVerifier(t)
			if tc.verifer != nil {
				tc.verifer(v)
			}
			if _, err := v.Verify(tok); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestVerify_ClaimAcceptances drives the passing branches of the optional checks.
func TestVerify_ClaimAcceptances(t *testing.T) {
	pinClock(t)
	t.Run("azp-correct", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["azp"] = testClient
		if _, err := rsVerifier(t).Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("azp correct: %v", err)
		}
	})
	t.Run("multi-aud-with-azp", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["aud"] = []any{testClient, "second"}
		c["azp"] = testClient
		if _, err := rsVerifier(t).Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("multi-aud azp: %v", err)
		}
	})
	t.Run("valid-nbf", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["nbf"] = fixedNow - 100
		if _, err := rsVerifier(t).Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("valid nbf: %v", err)
		}
	})
	t.Run("nonce-match", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "matchme")
		v := rsVerifier(t)
		v.Nonce = "matchme"
		if _, err := v.Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("nonce match: %v", err)
		}
	})
	t.Run("leeway-allows-expired", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["exp"] = fixedNow - 10
		v := rsVerifier(t)
		v.Leeway = 60 * time.Second
		if _, err := v.Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("leeway: %v", err)
		}
	})
}

// TestVerify_AtHashCHash covers the at_hash / c_hash branches.
func TestVerify_AtHashCHash(t *testing.T) {
	pinClock(t)
	access := "the-access-token"
	code := "the-auth-code"

	t.Run("both-match", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["at_hash"] = tokenHash(access, "RS256")
		c["c_hash"] = tokenHash(code, "RS256")
		v := rsVerifier(t)
		v.AccessToken, v.Code = access, code
		if _, err := v.Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("hash match: %v", err)
		}
	})
	t.Run("at_hash-mismatch", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["at_hash"] = "bogus"
		v := rsVerifier(t)
		v.AccessToken = access
		if _, err := v.Verify(signRS(t, "k1", c)); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("want ErrInvalidHash, got %v", err)
		}
	})
	t.Run("c_hash-mismatch", func(t *testing.T) {
		c := validClaims(testIssuer, testClient, "")
		c["c_hash"] = "bogus"
		v := rsVerifier(t)
		v.Code = code
		if _, err := v.Verify(signRS(t, "k1", c)); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("want ErrInvalidHash, got %v", err)
		}
	})
	t.Run("claim-absent-skips", func(t *testing.T) {
		// AccessToken supplied but token carries no at_hash — no error.
		c := validClaims(testIssuer, testClient, "")
		v := rsVerifier(t)
		v.AccessToken = access
		if _, err := v.Verify(signRS(t, "k1", c)); err != nil {
			t.Fatalf("absent at_hash: %v", err)
		}
	})
}

func TestTokenHash_Digests(t *testing.T) {
	// The 256 arm is covered via the at_hash tests; cover 384 and 512 here.
	if tokenHash("x", "RS384") == "" || tokenHash("x", "ES512") == "" {
		t.Fatal("empty hash")
	}
	if tokenHash("x", "RS384") == tokenHash("x", "ES512") {
		t.Fatal("384 and 512 hashes should differ")
	}
}

func TestNumericField(t *testing.T) {
	m := jwt.NewOrderedMap()
	m.Set("int", json.Number("42"))
	m.Set("float", json.Number("1.5"))
	m.Set("bad", json.Number("abc"))
	m.Set("f64", float64(7))
	m.Set("i64", int64(9))
	m.Set("i", int(11))
	m.Set("str", "nope")

	check := func(key string, wantN int64, wantOK bool) {
		n, ok := numericField(m, key)
		if n != wantN || ok != wantOK {
			t.Errorf("numericField(%q)=%d,%v want %d,%v", key, n, ok, wantN, wantOK)
		}
	}
	check("int", 42, true)
	check("float", 1, true)
	check("bad", 0, false)
	check("f64", 7, true)
	check("i64", 9, true)
	check("i", 11, true)
	check("str", 0, false)
	check("absent", 0, false)
}

func TestAudienceList(t *testing.T) {
	m := jwt.NewOrderedMap()
	if aud, ok := audienceList(m); ok || aud != nil {
		t.Errorf("absent aud: %v,%v", aud, ok)
	}
	m.Set("aud", "solo")
	if aud, ok := audienceList(m); !ok || len(aud) != 1 || aud[0] != "solo" {
		t.Errorf("string aud: %v,%v", aud, ok)
	}
	m2 := jwt.NewOrderedMap()
	m2.Set("aud", []any{"a", 123, "b"})
	if aud, ok := audienceList(m2); !ok || len(aud) != 2 {
		t.Errorf("array aud: %v,%v", aud, ok)
	}
	m3 := jwt.NewOrderedMap()
	m3.Set("aud", 123)
	if aud, ok := audienceList(m3); !ok || aud != nil {
		t.Errorf("numeric aud: %v,%v", aud, ok)
	}
}

func TestStringField(t *testing.T) {
	m := jwt.NewOrderedMap()
	m.Set("s", "v")
	m.Set("n", 1)
	if v, ok := stringField(m, "s"); !ok || v != "v" {
		t.Errorf("string: %q,%v", v, ok)
	}
	if _, ok := stringField(m, "n"); ok {
		t.Error("non-string reported present")
	}
	if _, ok := stringField(m, "absent"); ok {
		t.Error("absent reported present")
	}
}

func TestAlgMatchesKty(t *testing.T) {
	for _, tc := range []struct {
		alg, kty string
		want     bool
	}{
		{"RS256", "RSA", true},
		{"PS256", "RSA", true},
		{"ES256", "EC", true},
		{"ES256", "RSA", false},
		{"HS256", "oct", false},
	} {
		if got := algMatchesKty(tc.alg, tc.kty); got != tc.want {
			t.Errorf("algMatchesKty(%q,%q)=%v want %v", tc.alg, tc.kty, got, tc.want)
		}
	}
}
