package auth

import (
	"context"
	"encoding/json"
	"fmt"

	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
)

type JWKSCacheFetcher struct {
	cache *JWKSCache
}

func NewJWKSCacheFetcher(cache *JWKSCache) *JWKSCacheFetcher {
	return &JWKSCacheFetcher{cache: cache}
}

func (f *JWKSCacheFetcher) Get(ctx context.Context) ([]byte, error) {
	if f == nil || f.cache == nil {
		return nil, fmt.Errorf("jwks cache is nil")
	}

	set, err := f.cache.Get(ctx)
	if err != nil {
		return nil, err
	}

	return marshalJWKS(set)
}

func marshalJWKS(set *identity_v1.JWKSet) ([]byte, error) {
	if set == nil {
		return nil, fmt.Errorf("jwks set is nil")
	}

	payload := jwkSet{Keys: make([]jwkKey, 0, len(set.Keys))}
	for _, key := range set.Keys {
		if key == nil {
			continue
		}

		payload.Keys = append(payload.Keys, jwkKey{
			Kid: key.Kid,
			Kty: key.Kty,
			Use: key.Use,
			Alg: key.Alg,
			N:   key.N,
			E:   key.E,
			Crv: key.Crv,
			X:   key.X,
			Y:   key.Y,
		})
	}

	return json.Marshal(payload)
}
