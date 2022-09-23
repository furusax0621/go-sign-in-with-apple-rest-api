package siwarest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestClient_GenerateAndValidateTokens(t *testing.T) {
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

	t.Run("generate tokens using authorization code", func(t *testing.T) {
		wantToken := &TokenResponse{
			AccessToken:  "dummy-access-token",
			ExpiresIn:    3600,
			IDToken:      "dummy-id-token",
			RefreshToken: "dummy-refresh-token",
			TokenType:    "bearer",
		}

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if r.URL.Path != "/auth/token" {
				t.Errorf("invalid url path: want %s, got %s", "/auth/token", r.URL.Path)
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

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(wantToken)
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

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

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("invalid http method: want %s, got %s", http.MethodPost, r.Method)
			}

			if r.URL.Path != "/auth/token" {
				t.Errorf("invalid url path: want %s, got %s", "/auth/token", r.URL.Path)
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

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(wantToken)
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

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
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("client must return an error before this api is called")
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "code",
			RefreshToken:      "token",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})

	t.Run("authorization code and refresh token are empty, returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("client must return an error before this api is called")
		}))
		defer ts.Close()

		// override api endpoint
		baseURL, _ := url.Parse(ts.URL)
		c.baseURL = baseURL

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "",
			RefreshToken:      "",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
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

		input := &GenerateAndValidateTokensInput{
			AuthorizationCode: "dummy-auth-code",
		}
		if _, err := c.GenerateAndValidateTokens(context.TODO(), input); err == nil {
			t.Fatal("want error, but not")
		}
	})
}
