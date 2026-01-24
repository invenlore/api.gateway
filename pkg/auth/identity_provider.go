package auth

import (
	"context"
	"fmt"

	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
)

type IdentityJWKSProvider struct {
	client identity_v1.IdentityInternalServiceClient
}

func NewIdentityJWKSProvider(client identity_v1.IdentityInternalServiceClient) *IdentityJWKSProvider {
	return &IdentityJWKSProvider{client: client}
}

func (p *IdentityJWKSProvider) GetJWKS(ctx context.Context) (*identity_v1.JWKSet, error) {
	resp, err := p.client.GetJWKS(ctx, &identity_v1.GetJWKSRequest{})
	if err != nil {
		return nil, err
	}

	if resp == nil || resp.Jwks == nil {
		return nil, fmt.Errorf("identity jwks response is empty")
	}

	return resp.Jwks, nil
}
