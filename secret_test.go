package siwarest

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func Test_secret_get(t *testing.T) {
	secret := &secret{
		keyID:      "key-id",
		teamID:     "team-id",
		serviceID:  "service-id",
		privateKey: privateKey,
	}

	nowFunc = func() time.Time {
		return time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC) // in this test, now is 2022-06-30T00:00:00Z
	}
	defer func() { nowFunc = time.Now }()

	t.Run("call first time, generates new jwt", func(t *testing.T) {
		gotJWT, err := secret.get()
		if err != nil {
			t.Fatal(err)
		}

		var gotClaims jwt.RegisteredClaims
		_, err = jwt.ParseWithClaims(gotJWT, &gotClaims, func(tk *jwt.Token) (interface{}, error) {
			// check method
			if tk.Method != jwt.SigningMethodES256 {
				t.Errorf("want %v, got %v", jwt.SigningMethodES256, tk.Method)
			}

			// check alg header
			gotAlg := tk.Header["alg"].(string)
			if gotAlg != "ES256" {
				t.Errorf("want %s, got %s", "ES256", gotAlg)
			}

			// check kid header
			gotKid := tk.Header["kid"].(string)
			if gotKid != "key-id" {
				t.Errorf("want %s, got %s", "key-id", gotKid)
			}
			return publicKey, nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// check jwt claims
		if gotClaims.Issuer != "team-id" {
			t.Errorf("want %s, got %s", "team-id", gotClaims.Issuer)
		}
		if aud := gotClaims.Audience[0]; aud != "https://appleid.apple.com" {
			t.Errorf("want %s, got %s", "https://appleid.apple.com", aud)
		}
		if gotClaims.Subject != "service-id" {
			t.Errorf("want %s, got %s", "service-id", gotClaims.Subject)
		}
		if issuedAt := gotClaims.IssuedAt.Time; !issuedAt.Equal(time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("want %v, got %v", time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC), issuedAt)
		}
		if expiresAt := gotClaims.ExpiresAt.Time; !expiresAt.Equal(time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC).Add(expiresDuration)) {
			t.Errorf("want %v, got %v", time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC).Add(expiresDuration), expiresAt)
		}
	})

	t.Run("if secret has a jwt and it is valid, return existing jwt", func(t *testing.T) {
		wantToken := "existing-jwt-string"
		expiresAt := time.Date(2022, 6, 30, 1, 0, 1, 0, time.UTC)

		secret.tokenString = wantToken
		secret.expiresAt = expiresAt
		got, err := secret.get()
		if err != nil {
			t.Fatal(err)
		}

		if got != wantToken {
			t.Errorf("want %q, got %q", wantToken, got)
		}
		if !secret.expiresAt.Equal(expiresAt) {
			t.Errorf("want %v, got %v", expiresAt, secret.expiresAt)
		}
	})

	t.Run("if jwt has expired, refresh jwt", func(t *testing.T) {
		oldExpiresAt := time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC)
		secret.tokenString = "existing-jwt-string"
		secret.expiresAt = oldExpiresAt
		got, err := secret.get()
		if err != nil {
			t.Fatal(err)
		}

		if got == "existing-jwt-string" {
			t.Error("want new jwt string, but not")
		}
		if secret.tokenString != got {
			t.Errorf("want %s, got %s", got, secret.tokenString)
		}
		if secret.expiresAt.Equal(oldExpiresAt) {
			t.Error("want new expiresAt, but not")
		}
	})
}
