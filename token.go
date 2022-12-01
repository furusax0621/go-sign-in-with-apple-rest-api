package siwarest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GenerateAndValidateTokensInput is a parameter to call Generate and validate tokens API.
type GenerateAndValidateTokenInput interface {
	apply(*url.Values) error
}

type tokensInputWithAuthorizationCode struct {
	code string
}

func (g *tokensInputWithAuthorizationCode) apply(v *url.Values) error {
	if g.code == "" {
		return errors.New("siwarest: authorization_code is empty")
	}

	v.Add("grant_type", "authorization_code")
	v.Add("code", g.code)

	return nil
}

// GenerateAndValidateTokensWithAuthorizationCode is an authorization code received in an authorization response sent to your app.
func GenerateAndValidateTokensWithAuthorizationCode(code string) GenerateAndValidateTokenInput {
	return &tokensInputWithAuthorizationCode{
		code: code,
	}
}

type tokensInputWithRefreshToken struct {
	refreshToken string
}

func (g *tokensInputWithRefreshToken) apply(v *url.Values) error {
	if g.refreshToken == "" {
		return errors.New("siwarest: refresh_token is empty")
	}

	v.Add("grant_type", "refresh_token")
	v.Add("refresh_token", g.refreshToken)

	return nil
}

// GenerateAndValidateTokensWithRefreshToken is a refresh token received from the validation server during an authorization request.
func GenerateAndValidateTokensWithRefreshToken(refreshToken string) GenerateAndValidateTokenInput {
	return &tokensInputWithRefreshToken{
		refreshToken: refreshToken,
	}
}

// GenerateAndValidateTokens validates an authorization grant code delivered to your app to obtain tokens, or validate an existing refresh token.
//
// Please see also https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func (c *Client) GenerateAndValidateTokens(ctx context.Context, input GenerateAndValidateTokenInput) (*TokenResponse, error) {
	u := *c.baseURL
	u.Path = "/auth/token"

	body, err := c.newRequestBody()
	if err != nil {
		return nil, err
	}
	if err := input.apply(body); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("siwarest: failed to create request: %w", err)
	}
	c.setHeader(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("siwarest: failed to call api: %w", err)
	}
	defer resp.Body.Close()

	if err := c.validResponse(resp); err != nil {
		return nil, err
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("siwarest: failed to parse token response: %w", err)
	}

	return &tokenResponse, nil
}
