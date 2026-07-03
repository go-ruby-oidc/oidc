// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"testing"
)

func TestError_FamilyAndMessage(t *testing.T) {
	e := newError(ErrInvalidToken, "boom")
	if e.Error() != "boom" {
		t.Errorf("message=%q", e.Error())
	}
	if !errors.Is(e, ErrInvalidToken) || !errors.Is(e, ErrOIDC) {
		t.Error("family not matched")
	}
	if e.Kind != "InvalidToken" {
		t.Errorf("kind=%q", e.Kind)
	}
}

func TestError_WrapMatchesCause(t *testing.T) {
	cause := errors.New("underlying")
	e := wrapError(ErrJWKS, "outer", cause)
	if !errors.Is(e, ErrJWKS) || !errors.Is(e, ErrOIDC) {
		t.Error("family not matched")
	}
	if !errors.Is(e, cause) {
		t.Error("cause not matched")
	}
}

func TestKindOf_PlainSentinel(t *testing.T) {
	// ErrOIDC is a plain errors.New root, exercising kindOf's non-*Error arm.
	e := newError(ErrOIDC, "root")
	if e.Kind != "oidc" {
		t.Errorf("kind=%q", e.Kind)
	}
	w := wrapError(ErrOIDC, "root-wrap", errors.New("x"))
	if w.Kind != "oidc" {
		t.Errorf("wrap kind=%q", w.Kind)
	}
}
