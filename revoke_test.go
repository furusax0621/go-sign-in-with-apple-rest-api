package siwarest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClient_RevokeTokens(t *testing.T) {
	conf := &ClientConfig{
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
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if r.URL.Path != "/auth/revoke" {
				t.Errorf("invalid url path: want %s, got %s", "/auth/revoke", r.URL.Path)
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
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &RevokeTokensInput{
			AccessToken: "dummy-access-token",
		}
		if err := c.RevokeTokens(context.TODO(), input); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("revoke tokens using refresh token", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if r.URL.Path != "/auth/revoke" {
				t.Errorf("invalid url path: want %s, got %s", "/auth/revoke", r.URL.Path)
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
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &RevokeTokensInput{
			RefreshToken: "dummy-refresh-token",
		}
		if err := c.RevokeTokens(context.TODO(), input); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("both tokens are specified, returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("client must return an error before this api is called")
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &RevokeTokensInput{
			AccessToken:  "dummy-access-token",
			RefreshToken: "dummy-refresh-token",
		}
		if err := c.RevokeTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("both tokens are empty, returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("client must return an error before this api is called")
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &RevokeTokensInput{
			AccessToken:  "",
			RefreshToken: "",
		}
		if err := c.RevokeTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("if the api returns BadRequest, returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			body := ErrorResponse{
				Error: "invalid_request",
			}

			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(body)
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &RevokeTokensInput{
			AccessToken: "dummy-refresh-token",
		}
		if err := c.RevokeTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

}
