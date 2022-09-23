package siwarest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
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

	var tests = []struct {
		name    string
		code    int
		body    string
		wantKey string
	}{
		{
			name:    "bad request",
			code:    http.StatusBadRequest,
			body:    `{"error":"invalid_request"}`,
			wantKey: "error code: invalid_request",
		},
		{
			name:    "unknown error",
			code:    http.StatusInternalServerError,
			body:    `unknown error`,
			wantKey: "failed to parse error response: unknown error",
		},
	}

	for _, tc := range tests {
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
