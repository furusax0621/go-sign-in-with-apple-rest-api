package siwarest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GenerateAndValidateTokensInput is a parameter to call Generate and validate tokens API.
type GenerateAndValidateTokensInput struct {
	// AuthorizationCode is an authorization code received in an authorization response sent to your app.
	AuthorizationCode string
	// RefreshToken is a refresh token received from the validation server during an authorization request.
	RefreshToken string
}

// GenerateAndValidateTokens validates an authorization grant code delivered to your app to obtain tokens, or validate an existing refresh token.
//
// GenerateAndValidateTokensInput requires either an authorization code or a refresh token. If both are specified or both are empty, returns error.
//
// Please see also https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func (c *Client) GenerateAndValidateTokens(ctx context.Context, input *GenerateAndValidateTokensInput) (*TokenResponse, error) {
	var grantKey, grant, grantType string

	if input.AuthorizationCode == "" && input.RefreshToken == "" {
		return nil, errors.New("siwarest: authorization code and refresh token are empty")
	}

	if input.AuthorizationCode != "" {
		grantKey = "code"
		grant = input.AuthorizationCode
		grantType = "authorization_code"
	}

	if input.RefreshToken != "" {
		if input.AuthorizationCode != "" {
			return nil, errors.New("siwarest: both authorization code and refresh token are specified")
		}

		grantKey = "refresh_token"
		grant = input.RefreshToken
		grantType = "refresh_token"
	}

	u := *c.baseURL
	u.Path = "/auth/token"

	body, err := c.newRequestBody()
	if err != nil {
		return nil, err
	}
	body.Add("grant_type", grantType)
	body.Add(grantKey, grant)

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
