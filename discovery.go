// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProviderMetadata is a parsed OpenID Provider configuration
// (`.well-known/openid-configuration`), per OpenID Connect Discovery 1.0 §3. The
// named fields cover the members this library uses; Raw retains the full decoded
// document so a caller (or rbgo) can read provider extras.
type ProviderMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`

	// Raw is the whole decoded document, for members not promoted above.
	Raw map[string]any `json:"-"`
}

// discoveryURL builds the well-known configuration URL for an issuer, appending
// `/.well-known/openid-configuration` with exactly one separating slash (an
// issuer with a path keeps its path, per Discovery §4.1).
func discoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// ParseProviderMetadata decodes a discovery document, requiring the four members
// the code flow relies on — issuer, authorization_endpoint, token_endpoint and
// jwks_uri — to be present (a missing one is an [ErrDiscovery]).
func ParseProviderMetadata(data []byte) (*ProviderMetadata, error) {
	var pm ProviderMetadata
	if err := json.Unmarshal(data, &pm); err != nil {
		return nil, wrapError(ErrDiscovery, "discovery: malformed JSON: "+err.Error(), err)
	}
	// A second decode into a plain map keeps the full document for Raw; it cannot
	// fail once the first decode of the same bytes succeeded, so its error is not
	// inspected.
	var raw map[string]any
	json.Unmarshal(data, &raw) //nolint:errcheck // same bytes already validated
	pm.Raw = raw

	for _, req := range []struct{ name, val string }{
		{"issuer", pm.Issuer},
		{"authorization_endpoint", pm.AuthorizationEndpoint},
		{"token_endpoint", pm.TokenEndpoint},
		{"jwks_uri", pm.JWKSURI},
	} {
		if req.val == "" {
			return nil, newError(ErrDiscovery, "discovery: missing "+req.name)
		}
	}
	return &pm, nil
}

// Discover fetches and parses a provider's configuration document over the HTTP
// seam. It requires a 200 response and enforces that the document's issuer is
// identical to issuer (Discovery §4.3), rejecting a mismatch.
func Discover(doer Doer, issuer string) (*ProviderMetadata, error) {
	resp, err := fetch(doer, &HTTPRequest{Method: "GET", URL: discoveryURL(issuer)})
	if err != nil {
		return nil, wrapError(ErrDiscovery, "discovery fetch: "+err.Error(), err)
	}
	if resp.Status != 200 {
		return nil, newError(ErrDiscovery, fmt.Sprintf("discovery: unexpected status %d", resp.Status))
	}
	pm, err := ParseProviderMetadata([]byte(resp.Body))
	if err != nil {
		return nil, err
	}
	if pm.Issuer != issuer {
		return nil, newError(ErrDiscovery, "discovery: issuer mismatch: got "+pm.Issuer+", requested "+issuer)
	}
	return pm, nil
}
