package siwarest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClient_RevokeTokens(t *testing.T) {
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

	t.Run("revoke tokens using access token", func(t *testing.T) {
		mock := dummyRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if url := r.URL.String(); url != "https://appleid.apple.com/auth/revoke" {
				t.Errorf("invalid url: want %s, got %s", "https://appleid.apple.com/auth/revoke", url)
			}

			clientID := r.FormValue("client_id")
			if clientID != "dummy-client" {
				t.Errorf("invalid client_id: want %s, got %s", "dummy-client", clientID)
			}

			rt := r.FormValue("token")
			if rt != "dummy-access-token" {
				t.Errorf("invalid token: want %s, got %s", "dummy-access-token", rt)
			}

			tokenType := r.FormValue("token_type_hint")
			if tokenType != "access_token" {
				t.Errorf("invalid token_type_hint: want %s, got %s", "access_token", tokenType)
			}

			validateClientSecret(t, c, r.FormValue("client_secret"))

			resp := &http.Response{
				Header:     make(http.Header),
				StatusCode: http.StatusOK,
			}

			return resp, nil
		})
		hc.Transport = mock

		if err := c.RevokeTokens(context.TODO(), RevokeTokensInputWithAccessToken("dummy-access-token")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("revoke tokens using refresh token", func(t *testing.T) {
		mock := dummyRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if url := r.URL.String(); url != "https://appleid.apple.com/auth/revoke" {
				t.Errorf("invalid url: want %s, got %s", "https://appleid.apple.com/auth/revoke", url)
			}

			clientID := r.FormValue("client_id")
			if clientID != "dummy-client" {
				t.Errorf("invalid client_id: want %s, got %s", "dummy-client", clientID)
			}

			rt := r.FormValue("token")
			if rt != "dummy-refresh-token" {
				t.Errorf("invalid token: want %s, got %s", "dummy-refresh-token", rt)
			}

			tokenType := r.FormValue("token_type_hint")
			if tokenType != "refresh_token" {
				t.Errorf("invalid token_type_hint: want %s, got %s", "refresh_token", tokenType)
			}

			validateClientSecret(t, c, r.FormValue("client_secret"))

			resp := &http.Response{
				Header:     make(http.Header),
				StatusCode: http.StatusOK,
			}

			return resp, nil
		})
		hc.Transport = mock

		if err := c.RevokeTokens(context.TODO(), RevokeTokensInputWithRefreshToken("dummy-refresh-token")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("if access_token is empty, returns error", func(t *testing.T) {
		mock := dummyRoundTripper(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("client must return an error before this api is called")

			return nil, errors.New("invalid error")
		})
		hc.Transport = mock

		if err := c.RevokeTokens(context.TODO(), RevokeTokensInputWithAccessToken("")); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("if refresh_token is empty, returns error", func(t *testing.T) {
		mock := dummyRoundTripper(func(_ *http.Request) (*http.Response, error) {
			t.Fatal("client must return an error before this api is called")

			return nil, errors.New("invalid error")
		})
		hc.Transport = mock

		if err := c.RevokeTokens(context.TODO(), RevokeTokensInputWithRefreshToken("")); err == nil {
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

		if err := c.RevokeTokens(context.TODO(), RevokeTokensInputWithAccessToken("dummy-refresh-token")); err == nil {
			t.Fatal("want error, but not")
		}
	})
}
