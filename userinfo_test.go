// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"testing"
)

func TestParseUserInfo(t *testing.T) {
	u, err := ParseUserInfo([]byte(`{"sub":"u1","email":"a@b.c","email_verified":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if u.Subject() != "u1" {
		t.Errorf("Subject=%q", u.Subject())
	}
	if v, ok := u.Get("email"); !ok || v != "a@b.c" {
		t.Errorf("Get(email)=%v,%v", v, ok)
	}
	if _, ok := u.Get("absent"); ok {
		t.Error("absent present")
	}
	if u.Raw()["email_verified"] != true {
		t.Error("Raw email_verified")
	}
}

func TestParseUserInfo_Errors(t *testing.T) {
	if _, err := ParseUserInfo([]byte("{bad")); !errors.Is(err, ErrUserInfo) {
		t.Fatalf("malformed: want ErrUserInfo, got %v", err)
	}
	if _, err := ParseUserInfo([]byte(`{"name":"x"}`)); !errors.Is(err, ErrUserInfo) {
		t.Fatalf("no-sub: want ErrUserInfo, got %v", err)
	}
}

func TestFetchUserInfo(t *testing.T) {
	endpoint := "https://p/userinfo"

	t.Run("no-endpoint", func(t *testing.T) {
		if _, err := FetchUserInfo(newMockDoer(), "", "tok"); !errors.Is(err, ErrConfig) {
			t.Fatalf("want ErrConfig, got %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		d := newMockDoer().on(endpoint, `{"sub":"u1"}`)
		u, err := FetchUserInfo(d, endpoint, "access-xyz")
		if err != nil || u.Subject() != "u1" {
			t.Fatalf("fetch: %v %+v", err, u)
		}
		if d.last.Header["Authorization"] != "Bearer access-xyz" {
			t.Errorf("auth header=%q", d.last.Header["Authorization"])
		}
	})
	t.Run("transport-error", func(t *testing.T) {
		d := newMockDoer().onErr(endpoint, errors.New("x"))
		if _, err := FetchUserInfo(d, endpoint, "t"); !errors.Is(err, ErrUserInfo) || !errors.Is(err, ErrHTTP) {
			t.Fatalf("want ErrUserInfo+ErrHTTP, got %v", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		d := newMockDoer().onResp(endpoint, &HTTPResponse{Status: 401, Header: map[string]string{}, Body: ""})
		if _, err := FetchUserInfo(d, endpoint, "t"); !errors.Is(err, ErrUserInfo) {
			t.Fatalf("want ErrUserInfo, got %v", err)
		}
	})
}
