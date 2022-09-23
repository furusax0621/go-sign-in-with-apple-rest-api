package siwarest

// TokenResponse is the response token object returned on a successful request.
// https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type TokenResponse struct {
	// AccessToken is a token used to access allowed data, such as generating and exchanging transfer identifiers during user migration.
	AccessToken string `json:"access_token"`
	// ExpiresIn is the amount of time, in seconds, before the access token expires.
	ExpiresIn int `json:"expires_in"`
	// IDToken is a JSON Web Token (JWT) that contains the user’s identity information.
	IDToken string `json:"id_token"`
	// RefreshToken The refresh used to regenerate new access tokens when validating an authorization code.
	// Store this token securely on your server. The refresh token isn’t returned when validating an existing refresh token.
	RefreshToken string `json:"refresh_token"`
	// TokenType is the type of access token, which is always bearer.
	TokenType string `json:"token_type"`
}

// ErrorResponse is the error object returned after an unsuccessful request.
// https://developer.apple.com/documentation/sign_in_with_apple/errorresponse
type ErrorResponse struct {
	// Error is a string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
	Error string `json:"error"`
}
