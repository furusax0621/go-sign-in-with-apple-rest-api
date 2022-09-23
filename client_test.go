package siwarest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
