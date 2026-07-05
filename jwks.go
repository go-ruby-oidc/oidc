// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ruby-jwt/jwt"
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

// ParseJWKS decodes a JSON Web Key Set by delegating the RFC 7517 import to
// go-ruby-jwt's transport-agnostic ParseJWKS, then adapting each imported *jwt.JWK
// into this package's [Key]. The delegate materialises RSA and EC keys into crypto
// public keys and skips a key of any other type (e.g. an "oct" symmetric key),
// matching a client that ignores keys it cannot use for JWS verification; a key of
// a supported type with malformed material fails the whole set. Its jwt errors are
// re-wrapped under [ErrJWKS] so callers keep matching the OIDC error family.
func ParseJWKS(data []byte) (*KeySet, error) {
	js, err := jwt.ParseJWKS(data)
	if err != nil {
		return nil, wrapError(ErrJWKS, "jwks: "+err.Error(), err)
	}
	set := &KeySet{}
	for _, j := range js.Keys() {
		set.keys = append(set.keys, &Key{Kid: j.Kid, Kty: j.Kty, Alg: j.Alg, Use: j.Use, pub: j.PublicKey()})
	}
	return set, nil
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
