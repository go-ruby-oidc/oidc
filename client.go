// Copyright (c) the go-ruby-oidc/oidc authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"strings"
	"time"

	"github.com/go-ruby-oauth2/oauth2"
)

// Config configures an OIDC [Client] for the Authorization-Code + PKCE flow. The
// provider endpoints come from a discovery [ProviderMetadata]; the HTTP seam is
// the injectable [Doer].
type Config struct {
	// Metadata is the provider configuration (from Discover / ParseProviderMetadata).
	Metadata *ProviderMetadata
	// ClientID and ClientSecret are the registered client credentials. The secret
	// doubles as the HMAC key for HS-signed ID tokens.
	ClientID     string
	ClientSecret string
	// RedirectURI is the client's redirect endpoint.
	RedirectURI string
	// Scopes are extra scopes requested alongside the mandatory "openid".
	Scopes []string
	// Doer is the HTTP seam used for the token and userinfo requests.
	Doer Doer
	// Leeway is the clock-skew allowance for ID-token time checks.
	Leeway time.Duration
	// JWKSTTL is how long a fetched key set is cached (non-positive caches until a
	// kid miss).
	JWKSTTL time.Duration
}

// Client drives the OIDC Authorization-Code + PKCE flow: it builds the
// authorization URL, exchanges the code for tokens (reusing go-ruby-oauth2),
// verifies the returned ID token, and calls the userinfo endpoint.
type Client struct {
	cfg   Config
	oauth *oauth2.Client
	jwks  *JWKSCache
}

// NewClient builds a Client from a Config. It requires Metadata and a Doer.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Metadata == nil {
		return nil, newError(ErrConfig, "client: Metadata is required")
	}
	if cfg.Doer == nil {
		return nil, newError(ErrConfig, "client: Doer is required")
	}
	oc := oauth2.NewClient(cfg.ClientID, cfg.ClientSecret, oauth2.Options{
		AuthorizeURL: cfg.Metadata.AuthorizationEndpoint,
		TokenURL:     cfg.Metadata.TokenEndpoint,
	})
	return &Client{
		cfg:   cfg,
		oauth: oc,
		jwks:  NewJWKSCache(cfg.Doer, cfg.Metadata.JWKSURI, cfg.JWKSTTL),
	}, nil
}

// DiscoverClient runs discovery for issuer and returns a configured Client. It is
// a convenience over Discover + NewClient.
func DiscoverClient(cfg Config, issuer string) (*Client, error) {
	if cfg.Doer == nil {
		return nil, newError(ErrConfig, "client: Doer is required")
	}
	md, err := Discover(cfg.Doer, issuer)
	if err != nil {
		return nil, err
	}
	cfg.Metadata = md
	return NewClient(cfg)
}

// AuthParams carries the per-request inputs for [Client.AuthCodeURL].
type AuthParams struct {
	// State is the CSRF state value echoed back on the redirect.
	State string
	// Nonce binds the ID token to this request (recommended); echoed in the token.
	Nonce string
	// CodeVerifier is the PKCE verifier; when non-empty an S256 challenge is added
	// and the same verifier must be supplied to Exchange.
	CodeVerifier string
	// Scopes are additional scopes for this request (merged with the config's).
	Scopes []string
	// Extra carries any additional authorization params (prompt, login_hint, …).
	Extra oauth2.Params
}

// AuthCodeURL builds the authorization request URL to redirect the user-agent to:
// scope "openid" (plus configured/extra scopes), response_type=code, the client
// id, redirect_uri, state, nonce, and — when a CodeVerifier is given — the PKCE
// S256 code_challenge. The query is byte-faithful to go-ruby-oauth2's encoder.
func (c *Client) AuthCodeURL(p AuthParams) string {
	params := oauth2.Params{
		{Key: "redirect_uri", Val: c.cfg.RedirectURI},
		{Key: "scope", Val: mergeScopes(c.cfg.Scopes, p.Scopes)},
	}
	if p.State != "" {
		params = append(params, oauth2.Param{Key: "state", Val: p.State})
	}
	if p.Nonce != "" {
		params = append(params, oauth2.Param{Key: "nonce", Val: p.Nonce})
	}
	if p.CodeVerifier != "" {
		params = append(params,
			oauth2.Param{Key: "code_challenge", Val: oauth2.CodeChallenge(p.CodeVerifier, oauth2.PKCES256)},
			oauth2.Param{Key: "code_challenge_method", Val: string(oauth2.PKCES256)},
		)
	}
	params = append(params, p.Extra...)
	return c.oauth.AuthCode().AuthorizeURL(params)
}

// Tokens is the result of a successful code exchange.
type Tokens struct {
	// Access is the parsed OAuth2 access token (with any residual params).
	Access *oauth2.AccessToken
	// IDToken is the raw compact ID token JWT.
	IDToken string
	// Claims is the validated ID-token claim set.
	Claims *IDTokenClaims
}

// Exchange swaps an authorization code for tokens, then verifies the returned ID
// token. codeVerifier is the PKCE verifier from the matching [Client.AuthCodeURL]
// call (empty if PKCE was not used); nonce is the expected nonce (empty to skip
// the nonce check). The access token and code are used for at_hash/c_hash
// validation when those claims are present.
func (c *Client) Exchange(code, codeVerifier, nonce string) (*Tokens, error) {
	extra := oauth2.Params{{Key: "redirect_uri", Val: c.cfg.RedirectURI}}
	if codeVerifier != "" {
		extra = append(extra, oauth2.Param{Key: "code_verifier", Val: codeVerifier})
	}
	req := c.oauth.AuthCode().GetTokenRequest(code, extra)

	resp, err := (oauth2Transport{c.cfg.Doer}).RoundTrip(req)
	if err != nil {
		return nil, err
	}
	tok, err := c.oauth.ParseToken(resp)
	if err != nil {
		return nil, wrapError(ErrToken, "token endpoint: "+err.Error(), err)
	}
	idToken, _ := tok.Get("id_token")
	if idToken == "" {
		return nil, newError(ErrNoIDToken, "token response has no id_token")
	}

	v := c.Verifier()
	v.Nonce = nonce
	v.AccessToken = tok.Token
	v.Code = code
	claims, err := v.Verify(idToken)
	if err != nil {
		return nil, err
	}
	return &Tokens{Access: tok, IDToken: idToken, Claims: claims}, nil
}

// Verifier returns an ID-token [Verifier] bound to this client's provider issuer,
// client id, JWKS cache and HMAC secret (the client secret). Callers may set
// Nonce/AccessToken/Code before Verify for the optional checks.
func (c *Client) Verifier() *Verifier {
	return &Verifier{
		Issuer:     c.cfg.Metadata.Issuer,
		ClientID:   c.cfg.ClientID,
		Keys:       c.jwks,
		HMACSecret: []byte(c.cfg.ClientSecret),
		Leeway:     c.cfg.Leeway,
	}
}

// UserInfo calls the provider's userinfo endpoint with the bearer access token
// and returns the parsed claims.
func (c *Client) UserInfo(accessToken string) (*UserInfo, error) {
	return FetchUserInfo(c.cfg.Doer, c.cfg.Metadata.UserinfoEndpoint, accessToken)
}

// mergeScopes returns the space-joined scope string with "openid" first, followed
// by the configured and per-request scopes in order, de-duplicated.
func mergeScopes(configured, extra []string) string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append([]string{"openid"}, append(configured, extra...)...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
