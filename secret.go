package siwarest

import (
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const expiresDuration = 15777000 * time.Second
const expiresOffset = -1 * time.Hour

type secret struct {
	keyID       string
	teamID      string
	serviceID   string
	tokenString string
	privateKey  *ecdsa.PrivateKey
	expiresAt   time.Time
	mx          sync.Mutex
}

func newSecret(keyID, teamID, serviceID, privateKeyPEM string) (*secret, error) {
	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("siwarest: failed to parse pem: %w", err)
	}
	return &secret{
		keyID:      keyID,
		teamID:     teamID,
		serviceID:  serviceID,
		privateKey: privateKey,
	}, nil
}

func (s *secret) get() (string, error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	now := nowFunc().Truncate(time.Second)
	if s.tokenString == "" || s.expiresAt.Add(expiresOffset).Before(now) {
		token, expiresAt, err := s.generateClientSecret(now)
		if err != nil {
			return "", err
		}

		s.tokenString = token
		s.expiresAt = expiresAt
	}

	return s.tokenString, nil
}

func (s *secret) generateClientSecret(now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(expiresDuration)
	claim := jwt.RegisteredClaims{
		Issuer:    s.teamID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		Subject:   s.serviceID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claim)
	token.Header["kid"] = s.keyID

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("siwarest: failed to generate jwt claim: %w", err)
	}

	return tokenString, expiresAt, nil
}
