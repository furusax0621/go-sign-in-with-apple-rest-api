package siwarest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestClient_GenerateAndValidateTokens(t *testing.T) {
	hc := &http.Client{}

	conf := &ClientConfig{
		Client:        hc,
		ClientID:      "dummy-client",
		KeyID:         "dummy-key",
		TeamID:        "dummy-team",
		PrivateKeyPEM: privateKeyPEM,
	}

	c, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("generate tokens using authorization code", func(t *testing.T) {
		wantToken := &TokenResponse{
			AccessToken:  "dummy-access-token",
			ExpiresIn:    3600,
			IDToken:      "dummy-id-token",
			RefreshToken: "dummy-refresh-token",
			TokenType:    "bearer",
		}

		mock := dummyRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if url := r.URL.String(); url != "https://appleid.apple.com/auth/token" {
				t.Errorf("invalid url: want %s, got %s", "https://appleid.apple.com/auth/token", url)
			}

			clientID := r.FormValue("client_id")
			if clientID != "dummy-client" {
				t.Errorf("invalid client_id: want %s, got %s", "dummy-client", clientID)
			}

			grantType := r.FormValue("grant_type")
			if grantType != "authorization_code" {
				t.Errorf("invalid grant_type: want %s, got %s", "authorization_code", grantType)
			}

			code := r.FormValue("code")
			if code != "dummy-auth-code" {
				t.Errorf("invalid code: want %s, got %s", "dummy-auth-code", code)
			}

			validateClientSecret(t, c, r.FormValue("client_secret"))

			body, _ := json.Marshal(wantToken)
			resp := &http.Response{
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(body)),
				StatusCode: http.StatusOK,
			}

			return resp, nil
		})
		hc.Transport = mock

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "dummy-auth-code",
		}
		gotToken, err := c.GenerateAndValidateTokens(context.TODO(), input)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(wantToken, gotToken); diff != "" {
			t.Errorf("response mismatch (-want +got)\n%s", diff)
		}
	})

	t.Run("generate tokens using refresh token", func(t *testing.T) {
		wantToken := &TokenResponse{
			AccessToken:  "new-access-token",
			ExpiresIn:    1800,
			IDToken:      "new-id-token",
			RefreshToken: "new-refresh-token",
			TokenType:    "bearer",
		}

		mock := dummyRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if url := r.URL.String(); url != "https://appleid.apple.com/auth/token" {
				t.Errorf("invalid url: want %s, got %s", "https://appleid.apple.com/auth/token", url)
			}

			clientID := r.FormValue("client_id")
			if clientID != "dummy-client" {
				t.Errorf("invalid client_id: want %s, got %s", "dummy-client", clientID)
			}

			grantType := r.FormValue("grant_type")
			if grantType != "refresh_token" {
				t.Errorf("invalid grant_type: want %s, got %s", "refresh_token", grantType)
			}

			code := r.FormValue("refresh_token")
			if code != "old-refresh-token" {
				t.Errorf("invalid refresh_token: want %s, got %s", "old-refresh-token", code)
			}

			validateClientSecret(t, c, r.FormValue("client_secret"))

			body, _ := json.Marshal(wantToken)
			resp := &http.Response{
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(body)),
				StatusCode: http.StatusOK,
			}

			return resp, nil
		})
		hc.Transport = mock

		input := &GenerateAndValidateTokensInput{
			RefreshToken: "old-refresh-token",
		}
		gotToken, err := c.GenerateAndValidateTokens(context.TODO(), input)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(wantToken, gotToken); diff != "" {
			t.Errorf("response mismatch (-want +got)\n%s", diff)
		}
	})

	t.Run("both authorization code and refresh token are specified, returns error", func(t *testing.T) {
		mock := dummyRoundTripper(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("client must return an error before this api is called")

			return nil, errors.New("invalid error")
		})
		hc.Transport = mock

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "code",
			RefreshToken:      "token",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("authorization code and refresh token are empty, returns error", func(t *testing.T) {
		mock := dummyRoundTripper(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("client must return an error before this api is called")

			return nil, errors.New("invalid error")
		})
		hc.Transport = mock

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "",
			RefreshToken:      "",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("if the api returns BadRequest, returns error", func(t *testing.T) {
		mock := dummyRoundTripper(func(_ *http.Request) (*http.Response, error) {
			body := `{"error":"invalid_request"}`

			resp := &http.Response{
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				StatusCode: http.StatusBadRequest,
			}
			resp.Header.Add("content-type", "application/json")

			return resp, nil
		})
		hc.Transport = mock

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "dummy-auth-code",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})
}
