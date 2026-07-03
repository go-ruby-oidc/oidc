// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"github.com/go-ruby-oauth2/oauth2"
)

// HTTPRequest is the request the HTTP seam performs. It is intentionally minimal
// — method, URL, headers and a (form-encoded) body — so any host transport
// (go-ruby-net-http / faraday / a test mock) can satisfy it without depending on
// net/http types.
type HTTPRequest struct {
	// Method is "GET" or "POST".
	Method string
	// URL is the fully-qualified request URL (query already appended for GET).
	URL string
	// Header carries request headers (e.g. Authorization for userinfo).
	Header map[string]string
	// Body is the request body (form-encoded for a POST token request), or "".
	Body string
}

// HTTPResponse is the raw response the HTTP seam returns.
type HTTPResponse struct {
	// Status is the HTTP status code.
	Status int
	// Header carries response headers; Content-Type drives body parsing.
	Header map[string]string
	// Body is the raw response body.
	Body string
}

// Doer is the injectable HTTP seam: it performs one round-trip for a built
// [HTTPRequest] and returns the raw [HTTPResponse]. The core never opens a
// socket — a host (go-ruby-net-http / faraday) or a test mock implements this.
type Doer interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

// DoerFunc adapts a function to the [Doer] interface.
type DoerFunc func(req *HTTPRequest) (*HTTPResponse, error)

// Do calls f(req).
func (f DoerFunc) Do(req *HTTPRequest) (*HTTPResponse, error) { return f(req) }

// fetch performs a round-trip through the seam, wrapping a transport error as an
// [ErrHTTP]. It does not inspect the status — status handling is the caller's, so
// the token exchange can pass a 4xx body to oauth2's error parser.
func fetch(doer Doer, req *HTTPRequest) (*HTTPResponse, error) {
	resp, err := doer.Do(req)
	if err != nil {
		return nil, wrapError(ErrHTTP, req.Method+" "+req.URL+": "+err.Error(), err)
	}
	return resp, nil
}

// oauth2Transport adapts the oidc [Doer] to go-ruby-oauth2's RoundTripper so the
// authorization-code token exchange reuses the oauth2 request/response model over
// the single oidc HTTP seam.
type oauth2Transport struct{ doer Doer }

// RoundTrip converts an oauth2.Request into an [HTTPRequest], runs it through the
// seam, and converts the result back into an oauth2.Response for oauth2 to parse.
func (t oauth2Transport) RoundTrip(req *oauth2.Request) (*oauth2.Response, error) {
	hr := &HTTPRequest{
		Method: req.Method,
		URL:    req.FullURL(),
		Header: mapFromOAuth2(req.Headers),
		Body:   req.EncodedBody(),
	}
	resp, err := fetch(t.doer, hr)
	if err != nil {
		return nil, err
	}
	return oauth2.NewResponse(resp.Status, mapToOAuth2(resp.Header), resp.Body), nil
}

// mapFromOAuth2 renders an ordered oauth2.Map of headers as a plain string map.
func mapFromOAuth2(m *oauth2.Map) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	for _, p := range m.Pairs() {
		out[p.Key] = p.Val
	}
	return out
}

// mapToOAuth2 builds an ordered oauth2.Map from a plain header map so
// oauth2.Response can read the Content-Type for body dispatch.
func mapToOAuth2(h map[string]string) *oauth2.Map {
	m := oauth2.NewMap()
	for k, v := range h {
		m.Set(k, v)
	}
	return m
}
