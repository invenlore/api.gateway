package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

var (
	errKeyNotFound = errors.New("jwks key not found")
)

func MarshalJWKS(set *jwkSet) ([]byte, error) {
	if set == nil {
		return nil, fmt.Errorf("jwks set is nil")
	}

	return json.Marshal(set)
}

func ParseJWKS(raw []byte) (*jwkSet, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("jwks payload is empty")
	}

	var parsed jwkSet
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	return &parsed, nil
}

func (set *jwkSet) FindKey(kid string) (*jwkKey, error) {
	if set == nil || len(set.Keys) == 0 {
		return nil, errKeyNotFound
	}

	if kid == "" {
		return &set.Keys[0], nil
	}

	for _, key := range set.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}

	return nil, errKeyNotFound
}

func (key *jwkKey) ToPublicKey() (any, error) {
	if key == nil {
		return nil, fmt.Errorf("jwk key is nil")
	}

	switch key.Kty {
	case "RSA":
		return key.toRSAPublicKey()
	case "EC":
		return key.toECDSAPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

func (key *jwkKey) toRSAPublicKey() (*rsa.PublicKey, error) {
	if key.N == "" || key.E == "" {
		return nil, fmt.Errorf("missing rsa parameters")
	}

	modulus, err := decodeBase64URL(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}

	publicExp, err := decodeBase64URL(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	if len(publicExp) > 4 {
		return nil, fmt.Errorf("invalid exponent length")
	}

	e := 0
	for _, b := range publicExp {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}, nil
}

func (key *jwkKey) toECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if key.Crv == "" || key.X == "" || key.Y == "" {
		return nil, fmt.Errorf("missing ec parameters")
	}

	curve, err := curveByName(key.Crv)
	if err != nil {
		return nil, err
	}

	xBytes, err := decodeBase64URL(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := decodeBase64URL(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("empty base64url value")
	}

	return base64.RawURLEncoding.DecodeString(value)
}
