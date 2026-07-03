// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import "errors"

// Error is the shared error type this package raises. Kind names the failing
// category (mirroring the OpenID::Connect error families) and Message is the
// human-readable text. Every error Is [ErrOIDC], so a caller can match the whole
// family with errors.Is(err, oidc.ErrOIDC), or a specific one with the matching
// sentinel (e.g. errors.Is(err, oidc.ErrInvalidNonce)).
type Error struct {
	// Kind names the error category (e.g. "InvalidToken").
	Kind string
	// Message is the human-readable failure text.
	Message string
	// parent lets errors.Is walk to the family root and to any wrapped cause.
	parent error
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// Unwrap exposes the parent chain so errors.Is(err, ErrOIDC) — and any wrapped
// cause — matches.
func (e *Error) Unwrap() error { return e.parent }

// The sentinels below name the error categories. Match the whole family with
// errors.Is(err, oidc.ErrOIDC).
var (
	// ErrOIDC is the root every oidc error Is.
	ErrOIDC = errors.New("oidc")

	// ErrDiscovery is a failure fetching or parsing the discovery document.
	ErrDiscovery = newParent("Discovery", ErrOIDC)
	// ErrJWKS is a failure fetching or parsing the JSON Web Key Set.
	ErrJWKS = newParent("JWKS", ErrOIDC)
	// ErrHTTP is a transport/status failure from the HTTP seam.
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
	// ErrExpired is an ID token whose exp is in the past.
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

// newParent builds a sentinel whose Is chain reaches parent.
func newParent(kind string, parent error) error {
	return &Error{Kind: kind, Message: kind, parent: parent}
}

// newError constructs a failure of the given sentinel kind with a message. The
// sentinel supplies the parent chain so errors.Is spans the family.
func newError(sentinel error, msg string) *Error {
	var s *Error
	if errors.As(sentinel, &s) {
		return &Error{Kind: s.Kind, Message: msg, parent: sentinel}
	}
	return &Error{Kind: sentinel.Error(), Message: msg, parent: sentinel}
}

// wrapError constructs a failure of the given sentinel kind that also wraps an
// underlying cause, so errors.Is matches both the sentinel family and cause.
func wrapError(sentinel error, msg string, cause error) *Error {
	var s *Error
	kind := sentinel.Error()
	if errors.As(sentinel, &s) {
		kind = s.Kind
	}
	return &Error{Kind: kind, Message: msg, parent: &joined{sentinel: sentinel, cause: cause}}
}

// joined lets a wrapped error match both its sentinel family and its cause under
// errors.Is: Unwrap returns the sentinel, and Is defers to the cause too.
type joined struct {
	sentinel error
	cause    error
}

func (j *joined) Error() string { return j.sentinel.Error() }
func (j *joined) Unwrap() error { return j.sentinel }
func (j *joined) Is(target error) bool {
	return errors.Is(j.cause, target)
}
