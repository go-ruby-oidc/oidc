// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Key is one parsed JSON Web Key: a provider-assigned kid/alg/use and the RSA or
// EC public key it carries. Unlike the jwt gem's JWK (whose kid is a digest of the
// key), a provider's JWKS assigns the kid, so this type retains the provider's
// value for `kid`-based selection.
type Key struct {
	// Kid is the provider-assigned key id used to select the key.
	Kid string
	// Kty is the key type ("RSA" or "EC").
	Kty string
	// Alg is the intended algorithm ("RS256", "ES256", …), or "" if unspecified.
	Alg string
	// Use is the intended use ("sig"/"enc"), or "" if unspecified.
	Use string

	pub crypto.PublicKey
}

// PublicKey returns the parsed crypto public key (*rsa.PublicKey or
// *ecdsa.PublicKey), the value the jwt verifier consumes.
func (k *Key) PublicKey() crypto.PublicKey { return k.pub }

// KeySet is a parsed JSON Web Key Set (RFC 7517) — the signing keys of a
// provider, with selection by kid/alg.
type KeySet struct {
	keys []*Key
}

// Keys returns the set's keys in document order. The slice must not be mutated.
func (s *KeySet) Keys() []*Key { return s.keys }

// Find returns the key with the given kid, or nil.
func (s *KeySet) Find(kid string) *Key {
	for _, k := range s.keys {
		if k.Kid == kid {
			return k
		}
	}
	return nil
}

// Select resolves the verification key for a token, mirroring how a client picks
// the JWKS key: a non-empty kid selects that exact key; an empty kid falls back to
// the sole signing key whose type matches alg (rejecting an ambiguous set).
func (s *KeySet) Select(kid, alg string) (*Key, error) {
	if kid != "" {
		if k := s.Find(kid); k != nil {
			return k, nil
		}
		return nil, newError(ErrJWKS, "no key with kid "+kid)
	}
	var cands []*Key
	for _, k := range s.keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if !algMatchesKty(alg, k.Kty) {
			continue
		}
		cands = append(cands, k)
	}
	if len(cands) == 1 {
		return cands[0], nil
	}
	return nil, newError(ErrJWKS, "cannot select a signing key without a kid")
}

// algMatchesKty reports whether a JWS algorithm is served by a key type: the RSA
// families (RS/PS) by "RSA", the ECDSA family (ES) by "EC".
func algMatchesKty(alg, kty string) bool {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return kty == "RSA"
	case strings.HasPrefix(alg, "ES"):
		return kty == "EC"
	default:
		return false
	}
}

// jwkJSON is the wire shape of a single JWK member this library reads.
type jwkJSON struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksJSON is the wire shape of a key set.
type jwksJSON struct {
	Keys []jwkJSON `json:"keys"`
}

// ParseJWKS decodes a JSON Web Key Set. RSA and EC keys are materialised into
// crypto public keys; a key of any other type (e.g. an "oct" symmetric key) is
// skipped, matching a client that ignores keys it cannot use for JWS verification.
func ParseJWKS(data []byte) (*KeySet, error) {
	var doc jwksJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, wrapError(ErrJWKS, "jwks: malformed JSON: "+err.Error(), err)
	}
	set := &KeySet{}
	for _, j := range doc.Keys {
		pub, err := publicKeyFromJWK(j)
		if err != nil {
			return nil, err
		}
		if pub == nil { // unsupported key type — skip it.
			continue
		}
		set.keys = append(set.keys, &Key{Kid: j.Kid, Kty: j.Kty, Alg: j.Alg, Use: j.Use, pub: pub})
	}
	return set, nil
}

// publicKeyFromJWK builds the crypto public key for a JWK, returning (nil, nil)
// for an unsupported key type so the caller skips it.
func publicKeyFromJWK(j jwkJSON) (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		return rsaFromJWK(j)
	case "EC":
		return ecFromJWK(j)
	default:
		return nil, nil
	}
}

// rsaFromJWK builds an *rsa.PublicKey from the base64url modulus and exponent.
func rsaFromJWK(j jwkJSON) (crypto.PublicKey, error) {
	nb, err := b64url(j.N)
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks: bad RSA modulus: "+err.Error(), err)
	}
	eb, err := b64url(j.E)
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks: bad RSA exponent: "+err.Error(), err)
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, newError(ErrJWKS, "jwks: RSA key missing modulus or exponent")
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 1 {
		return nil, newError(ErrJWKS, "jwks: RSA exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// ecFromJWK builds an *ecdsa.PublicKey from the curve name and base64url
// coordinates. An off-curve point is left to the verifier to reject (ecdsa.Verify
// returns false), so no explicit on-curve check is duplicated here.
func ecFromJWK(j jwkJSON) (crypto.PublicKey, error) {
	crv, err := curveByName(j.Crv)
	if err != nil {
		return nil, err
	}
	xb, err := b64url(j.X)
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks: bad EC x: "+err.Error(), err)
	}
	yb, err := b64url(j.Y)
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks: bad EC y: "+err.Error(), err)
	}
	if len(xb) == 0 || len(yb) == 0 {
		return nil, newError(ErrJWKS, "jwks: EC key missing coordinate")
	}
	return &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// curveByName maps a JWA curve name to its elliptic.Curve.
func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, newError(ErrJWKS, "jwks: unsupported EC curve "+name)
	}
}

// b64url decodes a base64url segment, accepting the padded and unpadded forms.
func b64url(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// FetchJWKS retrieves and parses a key set from a JWKS URI over the HTTP seam,
// requiring a 200 response.
func FetchJWKS(doer Doer, uri string) (*KeySet, error) {
	resp, err := fetch(doer, &HTTPRequest{Method: "GET", URL: uri})
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks fetch: "+err.Error(), err)
	}
	if resp.Status != 200 {
		return nil, newError(ErrJWKS, "jwks: unexpected status "+strconv.Itoa(resp.Status))
	}
	return ParseJWKS([]byte(resp.Body))
}

// KeySource resolves a verification key by kid/alg. Both a static [KeySet] and a
// [JWKSCache] satisfy it, so a [Verifier] accepts either.
type KeySource interface {
	Select(kid, alg string) (*Key, error)
}

// JWKSCache fetches a provider's key set on demand and caches it for a TTL,
// refetching once when a requested kid is absent from the cached set (a key
// rotation). It is safe for concurrent use.
type JWKSCache struct {
	doer Doer
	uri  string
	ttl  time.Duration

	mu  sync.Mutex
	set *KeySet
	exp time.Time
}

// NewJWKSCache returns a cache that fetches from uri through doer and retains the
// set for ttl. A non-positive ttl caches until a kid miss forces a refetch.
func NewJWKSCache(doer Doer, uri string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{doer: doer, uri: uri, ttl: ttl}
}

// Get returns the cached key set, fetching (or refetching a stale set) as needed.
func (c *JWKSCache) Get() (*KeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	set, _, err := c.load()
	return set, err
}

// load returns the current set, whether it was fetched fresh this call, and any
// fetch error. It fetches when the cache is empty or expired.
func (c *JWKSCache) load() (*KeySet, bool, error) {
	if c.set != nil && nowFunc().Before(c.exp) {
		return c.set, false, nil
	}
	set, err := FetchJWKS(c.doer, c.uri)
	if err != nil {
		return nil, false, err
	}
	c.store(set)
	return set, true, nil
}

// store records a freshly fetched set and its expiry.
func (c *JWKSCache) store(set *KeySet) {
	c.set = set
	if c.ttl <= 0 {
		c.exp = time.Unix(1<<62, 0) // effectively never, until a kid miss forces refetch
		return
	}
	c.exp = nowFunc().Add(c.ttl)
}

// Select resolves a key by kid/alg from the cache. On a miss against a cached (not
// freshly fetched) set, it refetches once — covering a rotated signing key — and
// retries.
func (c *JWKSCache) Select(kid, alg string) (*Key, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	set, fetched, err := c.load()
	if err != nil {
		return nil, err
	}
	k, err := set.Select(kid, alg)
	if err == nil {
		return k, nil
	}
	if fetched {
		return nil, err // just fetched — the key really is absent.
	}
	fresh, ferr := FetchJWKS(c.doer, c.uri)
	if ferr != nil {
		return nil, ferr
	}
	c.store(fresh)
	return fresh.Select(kid, alg)
}
