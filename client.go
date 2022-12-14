package siwarest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var nowFunc = time.Now

// Client is a HTTP client.
type Client struct {
	hc       *http.Client
	clientID string
	baseURL  *url.URL
	secret   *secret
}

// ClientConfig saves parameters to setup Client.
type ClientConfig struct {
	// Client is the HTTP client. The default is http.DefaultClient.
	Client *http.Client
	// ClientID is an identifier (App ID or ClientID) for your app.
	ClientID string
	// KeyID is used to JWT claim. It is generated for the Sign in with Apple private key associated with your developer account.
	KeyID string
	// TeamID is used to JWT claim. Use your 10-character Team ID associated with your developer account.
	TeamID string
	// PrivateKeyPEM is used to sign the JWT of the client secret. Private key can be downloaded from Apple Developer.
	PrivateKeyPEM string
}

// New initializes Client.
func New(conf *ClientConfig) (*Client, error) {
	secret, err := newSecret(conf.KeyID, conf.TeamID, conf.ClientID, conf.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	hc := conf.Client
	if hc == nil {
		hc = http.DefaultClient
	}

	baseURL, _ := url.Parse("https://appleid.apple.com/")

	return &Client{
		hc:       hc,
		baseURL:  baseURL,
		clientID: conf.ClientID,
		secret:   secret,
	}, nil
}

func (c *Client) newRequestBody() (*url.Values, error) {
	secret, err := c.secret.get()
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	values.Add("client_id", c.clientID)
	values.Add("client_secret", secret)

	return &values, nil
}

func (c *Client) setHeader(req *http.Request) {
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
}

func (c *Client) validResponse(res *http.Response) error {
	if res.StatusCode == http.StatusOK {
		return nil
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("siwarest: failed to read response body: %w", err)
	}

	var ret ErrorResponse
	if err := json.Unmarshal(buf, &ret); err != nil {
		return fmt.Errorf("siwarest: status_code = %d, failed to parse error response, %s", res.StatusCode, string(buf))
	}

	switch ret.Error {
	case "invalid_request":
		return ErrInvalidRequest
	case "invalid_client":
		return ErrInvalidClient
	case "invalid_grant":
		return ErrInvalidGrant
	case "unauthorized_client":
		return ErrUnauthorizedClient
	case "unsupported_grant_type":
		return ErrUnsupportedGrantType
	case "invalid_scope":
		return ErrInvalidScope
	}

	return fmt.Errorf("siwarest: status_code = %d, unknown error code = %s", res.StatusCode, ret.Error)
}
