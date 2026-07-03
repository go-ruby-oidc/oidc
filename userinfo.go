// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"encoding/json"
	"strconv"
)

// UserInfo is the parsed response of the UserInfo endpoint (OIDC Core §5.3): the
// claims about the authenticated end-user. The response MUST carry a sub claim.
type UserInfo struct {
	raw map[string]any
}

// Subject returns the sub claim.
func (u *UserInfo) Subject() string {
	s, _ := u.raw["sub"].(string)
	return s
}

// Get returns a claim value and whether it is present.
func (u *UserInfo) Get(name string) (any, bool) {
	v, ok := u.raw[name]
	return v, ok
}

// Raw returns the full decoded claim set.
func (u *UserInfo) Raw() map[string]any { return u.raw }

// ParseUserInfo decodes a UserInfo JSON response, requiring a non-empty sub.
func ParseUserInfo(data []byte) (*UserInfo, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, wrapError(ErrUserInfo, "userinfo: malformed JSON: "+err.Error(), err)
	}
	sub, _ := raw["sub"].(string)
	if sub == "" {
		return nil, newError(ErrUserInfo, "userinfo: response has no sub")
	}
	return &UserInfo{raw: raw}, nil
}

// FetchUserInfo calls the userinfo endpoint with a bearer access token over the
// HTTP seam and parses the JSON claims. A missing endpoint or a non-200 response
// is an error.
func FetchUserInfo(doer Doer, endpoint, accessToken string) (*UserInfo, error) {
	if endpoint == "" {
		return nil, newError(ErrConfig, "userinfo: no userinfo endpoint")
	}
	resp, err := fetch(doer, &HTTPRequest{
		Method: "GET",
		URL:    endpoint,
		Header: map[string]string{"Authorization": "Bearer " + accessToken},
	})
	if err != nil {
		return nil, wrapError(ErrUserInfo, "userinfo fetch: "+err.Error(), err)
	}
	if resp.Status != 200 {
		return nil, newError(ErrUserInfo, "userinfo: unexpected status "+strconv.Itoa(resp.Status))
	}
	return ParseUserInfo([]byte(resp.Body))
}
