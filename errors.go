// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import "errors"

// Error is the error type this package raises. Kind names the failing category
// (mirroring the OpenID::Connect error families) and Message is the human-readable
// text. Every error Is [ErrOIDC], so a caller can match the whole family with
// errors.Is(err, oidc.ErrOIDC), a specific category with the matching sentinel
// (e.g. errors.Is(err, oidc.ErrInvalidNonce)), and — for a wrapped failure — the
// underlying cause too (e.g. a jwt sentinel).
type Error struct {
	// Kind names the error category (e.g. "InvalidToken").
	Kind string
	// Message is the human-readable failure text.
	Message string
	// parent is the sentinel family this error belongs to.
	parent error
	// cause is the wrapped underlying error, or nil.
	cause error
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// Unwrap exposes the family sentinel and, when present, the wrapped cause, so
// errors.Is matches both the oidc family and the original error.
func (e *Error) Unwrap() []error {
	if e.cause == nil {
		return []error{e.parent}
	}
	return []error{e.parent, e.cause}
}

// The sentinels below name the error categories. Match the whole family with
// errors.Is(err, oidc.ErrOIDC).
var (
	// ErrOIDC is the root every oidc error Is.
	ErrOIDC = errors.New("oidc")

	// ErrDiscovery is a failure fetching or parsing the discovery document.
	ErrDiscovery = newParent("Discovery", ErrOIDC)
	// ErrJWKS is a failure fetching or parsing the JSON Web Key Set.
	ErrJWKS = newParent("JWKS", ErrOIDC)
	// ErrHTTP is a transport failure from the HTTP seam.
	ErrHTTP = newParent("HTTP", ErrOIDC)
	// ErrInvalidToken is a malformed ID token or one whose signature/algorithm
	// could not be resolved or verified.
	ErrInvalidToken = newParent("InvalidToken", ErrOIDC)
	// ErrInvalidIssuer is an iss claim that does not match the expected issuer.
	ErrInvalidIssuer = newParent("InvalidIssuer", ErrOIDC)
	// ErrInvalidAudience is an aud claim that does not contain the client id.
	ErrInvalidAudience = newParent("InvalidAudience", ErrOIDC)
	// ErrInvalidAzp is an azp claim that is required-but-absent or does not match.
	ErrInvalidAzp = newParent("InvalidAzp", ErrOIDC)
	// ErrExpired is an ID token whose exp is in the past (or missing).
	ErrExpired = newParent("Expired", ErrOIDC)
	// ErrInvalidIat is an iat claim that is missing, malformed or in the future.
	ErrInvalidIat = newParent("InvalidIat", ErrOIDC)
	// ErrNotYetValid is an nbf claim still in the future.
	ErrNotYetValid = newParent("NotYetValid", ErrOIDC)
	// ErrInvalidNonce is a nonce claim that does not match the expected nonce.
	ErrInvalidNonce = newParent("InvalidNonce", ErrOIDC)
	// ErrInvalidHash is an at_hash/c_hash claim that does not match its value.
	ErrInvalidHash = newParent("InvalidHash", ErrOIDC)
	// ErrConfig is an invalid client/verifier configuration.
	ErrConfig = newParent("Config", ErrOIDC)
	// ErrNoIDToken is a token response without an id_token.
	ErrNoIDToken = newParent("NoIDToken", ErrOIDC)
	// ErrToken is a failure at the token endpoint (transport or OAuth2 error).
	ErrToken = newParent("Token", ErrOIDC)
	// ErrUserInfo is a failure fetching or parsing the userinfo response.
	ErrUserInfo = newParent("UserInfo", ErrOIDC)
)

// newParent builds a sentinel whose Unwrap chain reaches parent.
func newParent(kind string, parent error) error {
	return &Error{Kind: kind, Message: kind, parent: parent}
}

// kindOf returns the Kind of a sentinel: the wrapped *Error's Kind, or the plain
// error's text for a root sentinel (ErrOIDC).
func kindOf(sentinel error) string {
	var s *Error
	if errors.As(sentinel, &s) {
		return s.Kind
	}
	return sentinel.Error()
}

// newError constructs a failure of the given sentinel kind with a message.
func newError(sentinel error, msg string) *Error {
	return &Error{Kind: kindOf(sentinel), Message: msg, parent: sentinel}
}

// wrapError constructs a failure of the given sentinel kind that also wraps an
// underlying cause, so errors.Is matches the family and the cause.
func wrapError(sentinel error, msg string, cause error) *Error {
	return &Error{Kind: kindOf(sentinel), Message: msg, parent: sentinel, cause: cause}
}
