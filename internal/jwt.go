package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

type JWTClaims struct {
	jwt.RegisteredClaims

	Type              string   `json:"typ"`
	Scope             string   `json:"scope"`
	AuthorizedParty   string   `json:"azp"`
	ClientID          string   `json:"client_id"`
	Org               string   `json:"org"`
	Units             []string `json:"units,omitempty"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
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
