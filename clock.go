// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import "time"

// nowFunc is the clock the claim and cache logic reads; a test seam overrides it
// so the exp/iat/nbf and JWKS-TTL vectors are deterministic.
var nowFunc = time.Now
