package siwarest

import "errors"

var (
	// ErrInvalidRequest indicates that the request is malformed.
	ErrInvalidRequest = errors.New("siwarest: invalid_request")
	// ErrInvalidClient indicates that the client authentication failed.
	ErrInvalidClient = errors.New("siwarest: invalid_client")
	// ErrInvalidGrant indicates that the authorization grant or refresh token is invalid.
	ErrInvalidGrant = errors.New("siwarest: invalid_grant")
	// ErrUnauthorizedClient indicates that the client isn’t authorized to use this authorization grant type.
	ErrUnauthorizedClient = errors.New("siwarest: unauthorized_grant_type")
	// ErrUnsupportedGrantType indicates that the authenticated client isn’t authorized to use this grant type.
	ErrUnsupportedGrantType = errors.New("siwarest: unsupported_grant_type")
	// ErrInvalidScope indicates that the requested scope is invalid.
	ErrInvalidScope = errors.New("siwarest: invalid_scope")
)
