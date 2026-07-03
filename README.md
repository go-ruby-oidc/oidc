<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-oidc/brand/main/social/go-ruby-oidc-oidc.png" alt="go-ruby-oidc/oidc" width="720"></p>

# oidc — go-ruby-oidc

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-oidc.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) OpenID Connect library** — Discovery, JWKS, ID-token
verification, the Authorization-Code + PKCE flow, and UserInfo — mirroring the
surface of Ruby's [`openid_connect`](https://github.com/nov/openid_connect) gem
where it maps cleanly onto deterministic protocol logic, **without any Ruby
runtime**.

It is the OIDC layer for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but a
**standalone, reusable** module — a sibling of
[go-ruby-oauth2](https://github.com/go-ruby-oauth2/oauth2) and
[go-ruby-jwt](https://github.com/go-ruby-jwt/jwt), on which it builds.

> **What it consumes — and doesn't reinvent.** The OAuth2 authorization-URL and
> token-request construction come from
> [`go-ruby-oauth2/oauth2`](https://github.com/go-ruby-oauth2/oauth2); the ID
> token is a signed JWT parsed and signature-verified by
> [`go-ruby-jwt/jwt`](https://github.com/go-ruby-jwt/jwt). This package adds the
> OIDC-specific pieces: discovery, JWKS→key selection from a provider's key set,
> and the ID-token **claim** validation (iss, aud, exp, iat, nbf, nonce, azp,
> at_hash, c_hash).

> **The HTTP round-trip is a host seam.** Every network fetch (discovery, JWKS,
> token, userinfo) goes through the injectable `Doer` interface, so tests mock it
> and a host (go-embedded-ruby / rbgo) binds it without the core opening a
> socket. The token exchange reuses go-ruby-oauth2's request/response model via a
> small `Doer`→`oauth2.RoundTripper` adapter.

## Features

- **Discovery** — fetch and parse `.well-known/openid-configuration` into
  `ProviderMetadata` (issuer, authorization/token/userinfo/jwks endpoints,
  supported scopes/claims/algs), enforcing the issuer match.
- **JWKS** — fetch, parse and **cache** a provider's JSON Web Key Set
  (`KeySet` / `JWKSCache`) and **select the signing key by `kid`/`alg`**, with a
  one-shot refetch on a rotated key. RSA and EC keys are materialised from the
  JWK `n`/`e` and `crv`/`x`/`y`.
- **ID-token verification** — `Verifier` parses the ID token (via go-ruby-jwt),
  verifies the JWS signature (RS/ES/PS/HS families; **`none` is always rejected**)
  against the resolved key, and validates the OIDC claims: `iss` exact match,
  `aud` contains the client id, `exp`/`iat`/`nbf` with leeway, `nonce`, `azp`
  (required for multiple audiences), and `at_hash`/`c_hash` when present.
- **Authorization-Code + PKCE** — `Client.AuthCodeURL` builds the authorization
  request URL (scope `openid`, state, nonce, PKCE **S256** challenge) and
  `Client.Exchange` swaps the code for tokens via go-ruby-oauth2 and verifies the
  returned ID token.
- **UserInfo** — call the userinfo endpoint with the bearer access token and
  return the claims.

CGO-free, **100% test coverage** (every rejection branch), `gofmt` + `go vet`
clean, and green across the six 64-bit Go targets (amd64, arm64, riscv64,
loong64, ppc64le, s390x — including the big-endian lane).

## Install

```sh
go get github.com/go-ruby-oidc/oidc
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-oidc/oidc"
)

func main() {
	// doer is your HTTP seam: oidc.DoerFunc(func(*oidc.HTTPRequest) (*oidc.HTTPResponse, error){...})
	var doer oidc.Doer

	// 1. Discover the provider and build a client.
	client, err := oidc.DiscoverClient(oidc.Config{
		Doer:         doer,
		ClientID:     "myclient",
		ClientSecret: "mysecret",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"email", "profile"},
	}, "https://accounts.example.com")
	if err != nil {
		panic(err)
	}

	// 2. Build the authorization URL (openid scope + state + nonce + PKCE S256).
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authURL := client.AuthCodeURL(oidc.AuthParams{
		State:        "xyz",
		Nonce:        "n-0S6_WzA2Mj",
		CodeVerifier: verifier,
	})
	fmt.Println(authURL) // redirect the user-agent here

	// 3. On the redirect, exchange the code — the returned id_token is verified.
	tokens, err := client.Exchange("the-code", verifier, "n-0S6_WzA2Mj")
	if err != nil {
		panic(err)
	}
	fmt.Println(tokens.Claims.Subject(), tokens.Access.Token)

	// 4. Fetch UserInfo with the access token.
	ui, err := client.UserInfo(tokens.Access.Token)
	if err != nil {
		panic(err)
	}
	fmt.Println(ui.Subject())
}
```

### Verifying an ID token directly

```go
v := &oidc.Verifier{
	Issuer:   "https://accounts.example.com",
	ClientID: "myclient",
	Keys:     keySet, // *oidc.KeySet or *oidc.JWKSCache
	Nonce:    "n-0S6_WzA2Mj",
}
claims, err := v.Verify(idToken)
// err is errors.Is-matchable: ErrInvalidIssuer, ErrInvalidAudience, ErrExpired,
// ErrInvalidIat, ErrNotYetValid, ErrInvalidNonce, ErrInvalidAzp, ErrInvalidHash,
// ErrInvalidToken — all under ErrOIDC.
```

## The HTTP seam

```go
type Doer interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}
```

A `Doer` performs one round-trip. A host binds it to go-ruby-net-http / faraday;
tests supply an in-memory mock. Nothing in this package opens a socket.

## What it consumes

| capability | source |
| ---------- | ------ |
| authorization-URL + token-request construction, PKCE S256, token-response parsing | [`go-ruby-oauth2/oauth2`](https://github.com/go-ruby-oauth2/oauth2) |
| ID-token JWS parse + signature verify (RS/ES/PS/HS) | [`go-ruby-jwt/jwt`](https://github.com/go-ruby-jwt/jwt) |
| discovery, JWKS→key selection, OIDC claim validation, the flow orchestration | this package |

## API

```go
// Discovery
func Discover(doer Doer, issuer string) (*ProviderMetadata, error)
func ParseProviderMetadata(data []byte) (*ProviderMetadata, error)

// JWKS
func ParseJWKS(data []byte) (*KeySet, error)
func FetchJWKS(doer Doer, uri string) (*KeySet, error)
func NewJWKSCache(doer Doer, uri string, ttl time.Duration) *JWKSCache
func (s *KeySet) Select(kid, alg string) (*Key, error)     // also *JWKSCache
type KeySource interface{ Select(kid, alg string) (*Key, error) }

// ID token
type Verifier struct { Issuer, ClientID string; Keys KeySource; HMACSecret []byte; Nonce string; Leeway time.Duration; AccessToken, Code string; Algorithms []string }
func (v *Verifier) Verify(idToken string) (*IDTokenClaims, error)

// Flow
func NewClient(cfg Config) (*Client, error)
func DiscoverClient(cfg Config, issuer string) (*Client, error)
func (c *Client) AuthCodeURL(p AuthParams) string
func (c *Client) Exchange(code, codeVerifier, nonce string) (*Tokens, error)
func (c *Client) UserInfo(accessToken string) (*UserInfo, error)
func (c *Client) Verifier() *Verifier
```

## Tests & coverage

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

The suite verifies a known-good ID token validates and that tampered, expired,
wrong-`aud`, wrong-`iss`, wrong-`nonce`, bad-`azp` and bad-`at_hash`/`c_hash`
tokens are **rejected** — every rejection branch — plus the discovery/JWKS/token/
userinfo error paths (transport error, non-200, malformed JSON, missing `kid`,
unsupported alg, clock skew) over the mocked HTTP seam.

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-oidc/oidc authors.
