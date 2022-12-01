package siwarest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey
var privateKeyPEM string

func TestMain(m *testing.M) {
	// generate dummy key pair
	privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey = &privateKey.PublicKey

	sec1FormPrivateKey, _ := x509.MarshalECPrivateKey(privateKey)
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   sec1FormPrivateKey,
	})
	privateKeyPEM = buf.String()

	m.Run()
}

func TestClient_validResponse(t *testing.T) {
	c := &Client{}

	t.Run("if status code is ok, return nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
		}

		if err := c.validResponse(resp); err != nil {
			t.Fatal(err)
		}
	})

	// bad requests
	var badRequestTests = []struct {
		name string
		body string
		want error
	}{
		{
			name: "invalid_request",
			body: `{"error":"invalid_request"}`,
			want: ErrInvalidRequest,
		},
		{
			name: "invalid_client",
			body: `{"error":"invalid_client"}`,
			want: ErrInvalidClient,
		},
		{
			name: "invalid_grant",
			body: `{"error":"invalid_grant"}`,
			want: ErrInvalidGrant,
		},
		{
			name: "unauthorized_client",
			body: `{"error":"unauthorized_client"}`,
			want: ErrUnauthorizedClient,
		},
		{
			name: "unsupported_grant_type",
			body: `{"error":"unsupported_grant_type"}`,
			want: ErrUnsupportedGrantType,
		},
		{
			name: "invalid_scope",
			body: `{"error":"invalid_scope"}`,
			want: ErrInvalidScope,
		},
	}

	for _, tc := range badRequestTests {
		t.Run("BadRequest/"+tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}

			if err := c.validResponse(resp); !errors.Is(err, tc.want) {
				t.Errorf("unexpected error: want %v, got %v", tc.want, err)
			}
		})
	}

	// illegal cases
	var illegalTests = []struct {
		name    string
		code    int
		body    string
		wantKey string
	}{
		{
			name:    "bad request, unknown error code",
			code:    http.StatusBadRequest,
			body:    `{"error":"unknown_error"}`,
			wantKey: "status_code = 400, unknown error code = unknown_error",
		},
		{
			name:    "unknown error",
			code:    http.StatusInternalServerError,
			body:    `unknown error`,
			wantKey: "status_code = 500, failed to parse error response, unknown error",
		},
	}

	for _, tc := range illegalTests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.code,
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}

			err := c.validResponse(resp)
			if err == nil {
				t.Fatal("want error, but not")
			}
			msg := err.Error()
			if !strings.Contains(msg, fmt.Sprint(tc.code)) {
				t.Errorf("invalid error message: %s, want status code %d", msg, tc.code)
			}
			if !strings.Contains(msg, tc.wantKey) {
				t.Errorf("invalid error message: %s, want keyword %s", msg, tc.wantKey)
			}
		})
	}
}

func validateClientSecret(t *testing.T, c *Client, clientSecret string) {
	t.Helper()

	var claim jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(clientSecret, &claim, func(tk *jwt.Token) (interface{}, error) {
		// check method
		if tk.Method != jwt.SigningMethodES256 {
			t.Errorf("invalid sign method: want %v, got %v", jwt.SigningMethodES256, tk.Method)
		}

		// check alg header
		gotAlg := tk.Header["alg"].(string)
		if gotAlg != "ES256" {
			t.Errorf("invalid alg: want %s, got %s", "ES256", gotAlg)
		}

		// check kid header
		gotKid := tk.Header["kid"].(string)
		if gotKid != c.secret.keyID {
			t.Errorf("invalid kid: want %s, got %s", c.secret.keyID, gotKid)
		}
		return publicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if claim.Issuer != c.secret.teamID {
		t.Errorf("invalid iss: want %s, got %s", c.secret.teamID, claim.Issuer)
	}
	if aud := claim.Audience[0]; aud != "https://appleid.apple.com" {
		t.Errorf("invalid aud: want %s, got %s", "https://appleid.apple.com", aud)
	}
	if claim.Subject != c.clientID {
		t.Errorf("invalid sub: want %s, got %s", c.clientID, claim.Subject)
	}
}

var _ http.RoundTripper = (*dummyRoundTripper)(nil)

type dummyRoundTripper func(req *http.Request) (*http.Response, error)

func (r dummyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r(req)
}
