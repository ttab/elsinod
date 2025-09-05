package elsinod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ttab/elsinod/postgres"
)

var _ KeyStore = &DBKeystore{}

func NewDBKeyStore(
	ctx context.Context,
	conn postgres.DBTX,
) (*DBKeystore, error) {
	s := DBKeystore{
		conn: conn,
	}

	err := s.ensureSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("ensure signing keys: %w", err)
	}

	return &s, nil
}

type DBKeystore struct {
	conn postgres.DBTX
	km   sync.Mutex
	keys []StoreKey
}

// GetCurrentSigningKey implements KeyStore.
func (s *DBKeystore) GetCurrentSigningKey(_ context.Context) (StoreKey, error) {
	s.km.Lock()
	defer s.km.Unlock()

	return s.keys[0], nil
}

// GetKey implements KeyStore.
func (s *DBKeystore) GetKey(_ context.Context, id string) (StoreKey, error) {
	s.km.Lock()
	defer s.km.Unlock()

	for _, key := range s.keys {
		if key.ID != id {
			continue
		}

		return key, nil
	}

	return StoreKey{}, errors.New("unknown signing key")
}

// GetKeys implements KeyStore.
func (s *DBKeystore) GetKeys(_ context.Context) ([]StoreKey, error) {
	s.km.Lock()
	defer s.km.Unlock()

	return slices.Clone(s.keys), nil
}

type StoredSigningKey struct {
	Created time.Time
	PEM     string
}

func (s *DBKeystore) ensureSigningKeys(
	ctx context.Context,
) (outErr error) {
	s.km.Lock()
	defer s.km.Unlock()

	var known []string

	for _, k := range s.keys {
		known = append(known, k.JWK.ID)
	}

	q := postgres.New(s.conn)

	keyList, err := q.GetSigningKeys(ctx, known)
	if err != nil {
		return fmt.Errorf("load signing keys: %w", err)
	}

	for _, row := range keyList {
		var stored StoredSigningKey

		err = json.Unmarshal(keyList[0].Data, &stored)
		if err != nil {
			return fmt.Errorf("unmarshal stored key: %w", err)
		}

		key, err := DecodePrivateKey(stored.PEM)
		if err != nil {
			return fmt.Errorf("decode key %q: %w", row.ID, err)
		}

		s.keys = append(s.keys, StoreKey{
			ID:         row.ID,
			Created:    stored.Created,
			PrivateKey: key,
			JWK:        JWKFromEcdsa(row.ID, key),
		})
	}

	if len(s.keys) > 0 {
		return nil
	}

	key, err := NewSigningKey()
	if err != nil {
		return fmt.Errorf("create new signing key: %w", err)
	}

	pemEnc, err := EncodePrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode new key: %w", err)
	}

	created := time.Now()

	data, err := json.Marshal(StoredSigningKey{
		Created: created,
		PEM:     pemEnc,
	})
	if err != nil {
		return fmt.Errorf("marshal new key for storage: %w", err)
	}

	jwk := JWKFromEcdsa(uuid.NewString(), key)

	err = q.AddSigningKey(ctx, postgres.AddSigningKeyParams{
		ID:   jwk.ID,
		Data: data,
	})
	if err != nil {
		return fmt.Errorf("save new signing key: %w", err)
	}

	s.keys = append(s.keys, StoreKey{
		ID:         jwk.ID,
		Created:    created,
		PrivateKey: key,
		JWK:        jwk,
	})

	return nil
}
