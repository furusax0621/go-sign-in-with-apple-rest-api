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

	now := time.Now().Truncate(time.Second)
	nowFunc = func() time.Time {
		return now
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
		if issuedAt := gotClaims.IssuedAt.Time; !issuedAt.Equal(now) {
			t.Errorf("want %v, got %v", now, issuedAt)
		}
		if expiresAt := gotClaims.ExpiresAt.Time; !expiresAt.Equal(now.Add(expiresDuration)) {
			t.Errorf("want %v, got %v", now.Add(expiresDuration), expiresAt)
		}
	})

	t.Run("if secret has a jwt and it is valid, return existing jwt", func(t *testing.T) {
		wantToken := "existing-jwt-string"
		expiresAt := now.Add(time.Hour)

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
		oldExpiresAt := now
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
