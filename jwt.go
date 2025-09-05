package elsinod

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	jwtKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	return jwtKey, nil
}

func EncodePrivateKey(key *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("x509-encode key: %w", err)
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509Encoded,
	})

	return string(data), nil
}

func DecodePrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unknown block type %q", block.Type)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509 private key: %w", err)
	}

	return privateKey, nil
}

type JWTClaims struct {
	jwt.RegisteredClaims

	Type              string   `json:"typ"`
	Scope             string   `json:"scope"`
	AuthorizedParty   string   `json:"azp"`
	ClientID          string   `json:"client_id"`
	Org               string   `json:"org"`
	Units             []string `json:"units,omitempty"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	EmailVerified     bool     `json:"email_verified"`
}

func JWTToken(key *ecdsa.PrivateKey, keyID string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)

	token.Header["kid"] = keyID

	ss, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return ss, nil
}

type JWK struct {
	ID    string `json:"kid"`
	Type  string `json:"kty"`
	Algo  string `json:"alg"`
	Use   string `json:"use"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func JWKFromEcdsa(id string, key *ecdsa.PrivateKey) JWK {
	l := uint(key.Curve.Params().BitSize / 8) //nolint: gosec

	if key.Curve.Params().BitSize%8 != 0 {
		l++
	}

	return JWK{
		ID:    id,
		Type:  "EC",
		Algo:  "ES384",
		Use:   "sig",
		Curve: "P-384",
		X:     bigIntToBase64RawURL(key.X, l),
		Y:     bigIntToBase64RawURL(key.Y, l),
	}
}
