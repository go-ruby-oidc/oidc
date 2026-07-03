// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package oidc is a pure-Go (CGO-free) OpenID Connect library, the OIDC layer
// that sits on top of the go-ruby ecosystem's OAuth2 and JWT building blocks. It
// mirrors the surface of Ruby's `openid_connect` gem where that surface maps
// cleanly onto deterministic protocol logic, without any Ruby runtime.
//
// # What it does
//
//   - Discovery — fetch and parse a provider's
//     `.well-known/openid-configuration` document into [ProviderMetadata].
//   - JWKS — fetch, parse and cache a provider's JSON Web Key Set and select the
//     signing key by `kid`/`alg` ([KeySet], [JWKSCache]).
//   - ID-token verification — parse the ID token (a signed JWT, via
//     github.com/go-ruby-jwt/jwt), verify its signature against the JWKS key, and
//     validate the OIDC claims (iss, aud, exp, iat, nbf, nonce, azp, at_hash,
//     c_hash) with [Verifier].
//   - Authorization-Code + PKCE — build the authorization request URL and
//     exchange the code for tokens (built on
//     github.com/go-ruby-oauth2/oauth2), then verify the returned ID token
//     ([Client]).
//   - UserInfo — call the userinfo endpoint with an access token and return the
//     claims.
//
// # The HTTP seam
//
// Like the other go-ruby libraries, the network round-trip is a host seam: every
// fetch (discovery, JWKS, token, userinfo) goes through the injectable [Doer]
// interface, so tests mock it and a host (go-embedded-ruby / rbgo) binds it
// without the core opening a socket. The token exchange reuses go-ruby-oauth2's
// request/response model via a small [Doer]→oauth2.RoundTripper adapter.
//
// # What it consumes
//
// It builds on two siblings rather than re-implementing them:
//
//   - github.com/go-ruby-oauth2/oauth2 — the authorization-URL and token-request
//     construction and token-response parsing for the Authorization-Code+PKCE
//     grant.
//   - github.com/go-ruby-jwt/jwt — parsing and signature verification of the ID
//     token JWT (RS/ES/PS/HS families). JWKS→key selection from a provider's
//     JSON (which the jwt gem's JWK, keyed by its own digest, does not cover)
//     lives here, in [KeySet].
package oidc
