// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"testing"

	"github.com/go-ruby-oauth2/oauth2"
)

func TestDoerFunc(t *testing.T) {
	called := false
	f := DoerFunc(func(req *HTTPRequest) (*HTTPResponse, error) {
		called = true
		return &HTTPResponse{Status: 200}, nil
	})
	if _, err := f.Do(&HTTPRequest{}); err != nil || !called {
		t.Fatalf("DoerFunc not invoked: %v", err)
	}
}

func TestMapFromOAuth2_Nil(t *testing.T) {
	if got := mapFromOAuth2(nil); len(got) != 0 {
		t.Errorf("nil map: %v", got)
	}
	m := oauth2.NewMap()
	m.Set("A", "1")
	if got := mapFromOAuth2(m); got["A"] != "1" {
		t.Errorf("mapFromOAuth2: %v", got)
	}
}

func TestOAuth2Transport_RoundTrip(t *testing.T) {
	oc := oauth2.NewClient("id", "secret", oauth2.Options{TokenURL: "https://p/token"})

	t.Run("post-success", func(t *testing.T) {
		var seen *HTTPRequest
		d := DoerFunc(func(req *HTTPRequest) (*HTTPResponse, error) {
			seen = req
			return &HTTPResponse{Status: 200, Header: map[string]string{"Content-Type": "application/json"},
				Body: `{"access_token":"t"}`}, nil
		})
		req := oc.AuthCode().GetTokenRequest("code", nil)
		resp, err := (oauth2Transport{d}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 || seen.Method != "POST" || seen.Body == "" {
			t.Errorf("roundtrip: status=%d method=%s body=%q", resp.Status, seen.Method, seen.Body)
		}
		if seen.Header["Content-Type"] != "application/x-www-form-urlencoded" {
			t.Errorf("content-type header=%q", seen.Header["Content-Type"])
		}
	})

	t.Run("transport-error", func(t *testing.T) {
		d := DoerFunc(func(req *HTTPRequest) (*HTTPResponse, error) {
			return nil, errors.New("down")
		})
		req := oc.AuthCode().GetTokenRequest("code", nil)
		if _, err := (oauth2Transport{d}).RoundTrip(req); !errors.Is(err, ErrHTTP) {
			t.Fatalf("want ErrHTTP, got %v", err)
		}
	})

	t.Run("get-method", func(t *testing.T) {
		ocGet := oauth2.NewClient("id", "secret", oauth2.Options{
			TokenURL: "https://p/token", TokenMethod: oauth2.TokenGet})
		var seen *HTTPRequest
		d := DoerFunc(func(req *HTTPRequest) (*HTTPResponse, error) {
			seen = req
			return &HTTPResponse{Status: 200, Header: map[string]string{}, Body: ""}, nil
		})
		req := ocGet.AuthCode().GetTokenRequest("code", nil)
		if _, err := (oauth2Transport{d}).RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		if seen.Method != "GET" || seen.Body != "" {
			t.Errorf("GET roundtrip: method=%s body=%q url=%s", seen.Method, seen.Body, seen.URL)
		}
	})
}
