package elsinod

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

type KeyStore interface {
	GetKeys(ctx context.Context) ([]StoreKey, error)
	GetKey(ctx context.Context, id string) (StoreKey, error)
	GetCurrentSigningKey(ctx context.Context) (StoreKey, error)
}

type StoreKey struct {
	ID         string
	Created    time.Time
	PrivateKey *ecdsa.PrivateKey
	JWK        JWK
}

var _ KeyStore = &StaticKeyStore{}

func NewStaticKeyStore(id string, key *ecdsa.PrivateKey) *StaticKeyStore {
	return &StaticKeyStore{
		k: StoreKey{
			ID:         id,
			Created:    time.Now(),
			PrivateKey: key,
			JWK:        JWKFromEcdsa(id, key),
		},
	}
}

type StaticKeyStore struct {
	k StoreKey
}

// GetCurrentSigningKey implements KeyStore.
func (s *StaticKeyStore) GetCurrentSigningKey(_ context.Context) (StoreKey, error) {
	return s.k, nil
}

// GetKey implements KeyStore.
func (s *StaticKeyStore) GetKey(_ context.Context, id string) (StoreKey, error) {
	if id != s.k.ID {
		return StoreKey{}, errors.New("unknown signing key")
	}

	return s.k, nil
}

// GetKeys implements KeyStore.
func (s *StaticKeyStore) GetKeys(_ context.Context) ([]StoreKey, error) {
	return []StoreKey{s.k}, nil
}
