// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-ruby-jwt/jwt"
)

// defaultAlgs is the set of JWS algorithms accepted for an ID token when a
// Verifier does not restrict them. "none" is never accepted — an OIDC ID token
// must be signed.
var defaultAlgs = []string{
	"HS256", "HS384", "HS512",
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
}

// Verifier validates an OpenID Connect ID token: it resolves the signing key,
// verifies the JWS signature (via github.com/go-ruby-jwt/jwt), and checks the
// OIDC claims. The signature check is delegated to the jwt sibling; every OIDC
// claim rule (iss, aud, exp, iat, nbf, nonce, azp, at_hash, c_hash) is applied
// here so the accepted/rejected semantics are OIDC-specific.
type Verifier struct {
	// Issuer is the expected iss value (exact match).
	Issuer string
	// ClientID is the expected audience member (and azp value).
	ClientID string
	// Keys resolves the RSA/EC signing key by kid/alg (a KeySet or JWKSCache).
	Keys KeySource
	// HMACSecret is the shared secret for HS* tokens (typically the client
	// secret); required only when an HS-family token is verified.
	HMACSecret []byte
	// Nonce, when non-empty, is the expected nonce claim.
	Nonce string
	// Leeway is the allowed clock skew for the exp/iat/nbf checks.
	Leeway time.Duration
	// AccessToken, when non-empty, enables at_hash validation against it.
	AccessToken string
	// Code, when non-empty, enables c_hash validation against it.
	Code string
	// Algorithms optionally restricts the accepted alg values; empty means
	// defaultAlgs.
	Algorithms []string
}

// IDTokenClaims is the validated payload of an ID token. The typed accessors
// cover the standard OIDC claims; Get/String and Raw expose the rest.
type IDTokenClaims struct {
	raw *jwt.OrderedMap
}

// Verify parses idToken, verifies its signature against the resolved key, and
// applies the OIDC claim checks. On success it returns the validated claims; any
// failure is an error whose family (errors.Is) identifies the failing check.
func (v *Verifier) Verify(idToken string) (*IDTokenClaims, error) {
	// Parse (without verifying) to read the header and choose the key.
	_, header, err := jwt.Decode(idToken, nil, false, jwt.Options{})
	if err != nil {
		return nil, wrapError(ErrInvalidToken, "id token: "+err.Error(), err)
	}
	hm, ok := header.(*jwt.OrderedMap)
	if !ok {
		return nil, newError(ErrInvalidToken, "id token: header is not an object")
	}
	alg, ok := stringField(hm, "alg")
	if !ok {
		return nil, newError(ErrInvalidToken, "id token: header has no alg")
	}
	if alg == "none" {
		return nil, newError(ErrInvalidToken, "id token: unsigned (alg none) rejected")
	}
	if !containsFold(v.effectiveAlgs(), alg) {
		return nil, newError(ErrInvalidToken, "id token: unsupported algorithm "+alg)
	}

	key, err := v.keyFor(alg, hm)
	if err != nil {
		return nil, err
	}

	// Verify the signature only (exp/nbf are checked here, not by jwt, so the
	// OIDC error semantics and clock seam apply).
	payload, _, err := jwt.Decode(idToken, key, true, jwt.Options{
		Algorithms:          []string{alg},
		VerifyExpiration:    false,
		VerifyExpirationSet: true,
		VerifyNotBefore:     false,
		VerifyNotBeforeSet:  true,
	})
	if err != nil {
		return nil, wrapError(ErrInvalidToken, "id token signature: "+err.Error(), err)
	}

	claims, ok := payload.(*jwt.OrderedMap)
	if !ok {
		return nil, newError(ErrInvalidToken, "id token: payload is not an object")
	}
	if err := v.verifyClaims(claims, alg); err != nil {
		return nil, err
	}
	return &IDTokenClaims{raw: claims}, nil
}

// effectiveAlgs returns the configured algorithm allow-list, or the default.
func (v *Verifier) effectiveAlgs() []string {
	if len(v.Algorithms) > 0 {
		return v.Algorithms
	}
	return defaultAlgs
}

// keyFor resolves the verification key for an algorithm: the HMAC secret for an
// HS-family token, else the JWKS key selected by the header kid.
func (v *Verifier) keyFor(alg string, header *jwt.OrderedMap) (any, error) {
	if strings.HasPrefix(alg, "HS") {
		if len(v.HMACSecret) == 0 {
			return nil, newError(ErrConfig, "id token: HS algorithm requires an HMAC secret")
		}
		return v.HMACSecret, nil
	}
	if v.Keys == nil {
		return nil, newError(ErrConfig, "id token: no key source configured")
	}
	kid, _ := stringField(header, "kid")
	k, err := v.Keys.Select(kid, alg)
	if err != nil {
		return nil, wrapError(ErrInvalidToken, "id token key: "+err.Error(), err)
	}
	return k.PublicKey(), nil
}

// verifyClaims applies the OIDC claim rules in a fixed order.
func (v *Verifier) verifyClaims(claims *jwt.OrderedMap, alg string) error {
	if err := v.verifyIssuer(claims); err != nil {
		return err
	}
	aud, err := v.verifyAudience(claims)
	if err != nil {
		return err
	}
	if err := v.verifyAzp(claims, aud); err != nil {
		return err
	}
	if err := v.verifyExp(claims); err != nil {
		return err
	}
	if err := v.verifyIat(claims); err != nil {
		return err
	}
	if err := v.verifyNbf(claims); err != nil {
		return err
	}
	if err := v.verifyNonce(claims); err != nil {
		return err
	}
	if err := v.verifyHash(claims, "at_hash", v.AccessToken, alg); err != nil {
		return err
	}
	return v.verifyHash(claims, "c_hash", v.Code, alg)
}

// verifyIssuer requires iss to be present and identical to the expected issuer.
func (v *Verifier) verifyIssuer(claims *jwt.OrderedMap) error {
	iss, ok := stringField(claims, "iss")
	if !ok || iss != v.Issuer {
		return newError(ErrInvalidIssuer, "id token: iss does not match "+v.Issuer)
	}
	return nil
}

// verifyAudience requires aud (string or array) to contain the client id, and
// returns the audience list for the azp check.
func (v *Verifier) verifyAudience(claims *jwt.OrderedMap) ([]string, error) {
	aud, present := audienceList(claims)
	if !present {
		return nil, newError(ErrInvalidAudience, "id token: missing aud")
	}
	for _, a := range aud {
		if a == v.ClientID {
			return aud, nil
		}
	}
	return nil, newError(ErrInvalidAudience, "id token: aud does not contain "+v.ClientID)
}

// verifyAzp checks the authorized-party claim: it must equal the client id when
// present, and must be present when the audience has more than one member.
func (v *Verifier) verifyAzp(claims *jwt.OrderedMap, aud []string) error {
	azp, present := stringField(claims, "azp")
	if present {
		if azp != v.ClientID {
			return newError(ErrInvalidAzp, "id token: azp does not match "+v.ClientID)
		}
		return nil
	}
	if len(aud) > 1 {
		return newError(ErrInvalidAzp, "id token: azp required for multiple audiences")
	}
	return nil
}

// verifyExp requires exp and rejects an expired token (now >= exp + leeway).
func (v *Verifier) verifyExp(claims *jwt.OrderedMap) error {
	exp, ok := numericField(claims, "exp")
	if !ok {
		return newError(ErrExpired, "id token: missing or malformed exp")
	}
	if nowFunc().Unix() >= exp+v.leewaySecs() {
		return newError(ErrExpired, "id token: expired")
	}
	return nil
}

// verifyIat requires iat and rejects a token issued in the future (iat > now +
// leeway).
func (v *Verifier) verifyIat(claims *jwt.OrderedMap) error {
	iat, ok := numericField(claims, "iat")
	if !ok {
		return newError(ErrInvalidIat, "id token: missing or malformed iat")
	}
	if iat > nowFunc().Unix()+v.leewaySecs() {
		return newError(ErrInvalidIat, "id token: iat is in the future")
	}
	return nil
}

// verifyNbf rejects a token that is not yet valid (now < nbf - leeway). nbf is
// optional.
func (v *Verifier) verifyNbf(claims *jwt.OrderedMap) error {
	nbf, ok := numericField(claims, "nbf")
	if !ok {
		return nil
	}
	if nowFunc().Unix() < nbf-v.leewaySecs() {
		return newError(ErrNotYetValid, "id token: not yet valid (nbf)")
	}
	return nil
}

// verifyNonce checks the nonce claim against the expected value when one is set.
func (v *Verifier) verifyNonce(claims *jwt.OrderedMap) error {
	if v.Nonce == "" {
		return nil
	}
	n, ok := stringField(claims, "nonce")
	if !ok || n != v.Nonce {
		return newError(ErrInvalidNonce, "id token: nonce does not match")
	}
	return nil
}

// verifyHash checks an at_hash/c_hash claim against value when both the value and
// the claim are present. It is a no-op when value is empty or the claim is absent
// (the hash claims are optional in the code flow).
func (v *Verifier) verifyHash(claims *jwt.OrderedMap, name, value, alg string) error {
	if value == "" {
		return nil
	}
	got, ok := stringField(claims, name)
	if !ok {
		return nil
	}
	if got != tokenHash(value, alg) {
		return newError(ErrInvalidHash, "id token: "+name+" does not match")
	}
	return nil
}

// leewaySecs is the verifier's clock-skew allowance in whole seconds.
func (v *Verifier) leewaySecs() int64 { return int64(v.Leeway / time.Second) }

// tokenHash is the OIDC at_hash/c_hash: the base64url of the left-most half of the
// hash (chosen by the alg's digest) of the ASCII value (OIDC Core §3.1.3.6).
func tokenHash(value, alg string) string {
	var sum []byte
	switch alg[len(alg)-3:] {
	case "384":
		h := sha512.Sum384([]byte(value))
		sum = h[:]
	case "512":
		h := sha512.Sum512([]byte(value))
		sum = h[:]
	default: // "256"
		h := sha256.Sum256([]byte(value))
		sum = h[:]
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// --- claim accessors --------------------------------------------------------

// Get returns a raw claim value and whether it is present.
func (c *IDTokenClaims) Get(name string) (any, bool) { return c.raw.Get(name) }

// String returns a string-valued claim and whether it is present as a string.
func (c *IDTokenClaims) String(name string) (string, bool) { return stringField(c.raw, name) }

// Issuer returns the iss claim.
func (c *IDTokenClaims) Issuer() string { s, _ := stringField(c.raw, "iss"); return s }

// Subject returns the sub claim.
func (c *IDTokenClaims) Subject() string { s, _ := stringField(c.raw, "sub"); return s }

// Nonce returns the nonce claim.
func (c *IDTokenClaims) Nonce() string { s, _ := stringField(c.raw, "nonce"); return s }

// Audience returns the aud claim as a slice (a single string audience becomes a
// one-element slice).
func (c *IDTokenClaims) Audience() []string { aud, _ := audienceList(c.raw); return aud }

// ExpiresAt returns the exp claim as a Unix timestamp (0 if absent).
func (c *IDTokenClaims) ExpiresAt() int64 { n, _ := numericField(c.raw, "exp"); return n }

// IssuedAt returns the iat claim as a Unix timestamp (0 if absent).
func (c *IDTokenClaims) IssuedAt() int64 { n, _ := numericField(c.raw, "iat"); return n }

// Raw returns the underlying ordered claim map.
func (c *IDTokenClaims) Raw() *jwt.OrderedMap { return c.raw }

// --- helpers ----------------------------------------------------------------

// stringField reads a string-valued member from an ordered map.
func stringField(m *jwt.OrderedMap, key string) (string, bool) {
	v, ok := m.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// numericField reads a numeric member as an int64, accepting the json.Number the
// jwt decoder produces (and plain float/int for constructed maps).
func numericField(m *jwt.OrderedMap, key string) (int64, bool) {
	v, ok := m.Get(key)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil {
			return int64(f), true
		}
		return 0, false
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// audienceList reads aud as a list: a string yields one element, an array yields
// its string elements. The bool reports whether aud was present at all.
func audienceList(m *jwt.OrderedMap) ([]string, bool) {
	v, ok := m.Get("aud")
	if !ok {
		return nil, false
	}
	switch a := v.(type) {
	case string:
		return []string{a}, true
	case []any:
		var out []string
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, true
	}
}

// containsFold reports whether want is in list under case-insensitive comparison.
func containsFold(list []string, want string) bool {
	for _, e := range list {
		if strings.EqualFold(e, want) {
			return true
		}
	}
	return false
}
