// Package oidcidentity defines the non-secret server OIDC configuration and
// identity-assertion contract. Raw compact tokens never enter these types.
package oidcidentity

import "github.com/ArronJablonowski/COH/internal/domain/localidentity"

const (
	SchemaVersion   = "coh.server-oidc/v1"
	ContractVersion = "1.0.0"
)

type ProviderConfig struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	ProfileKind            string   `json:"profile_kind"`
	Issuer                 string   `json:"issuer"`
	Audiences              []string `json:"audiences"`
	AllowedAlgorithms      []string `json:"allowed_algorithms"`
	JWKSReference          string   `json:"jwks_source_reference"`
	TransportSecurity      string   `json:"transport_security"`
	ProfileDecisionDigest  string   `json:"profile_decision_digest"`
	MaximumTokenAgeSeconds uint32   `json:"maximum_token_age_seconds"`
	ClockSkewSeconds       uint32   `json:"clock_skew_seconds"`
}

type Claims struct {
	Issuer         string               `json:"iss"`
	Subject        string               `json:"sub"`
	Audiences      []string             `json:"aud"`
	ExpiresAt      int64                `json:"exp"`
	IssuedAt       int64                `json:"iat"`
	NotBefore      int64                `json:"nbf"`
	JWTID          string               `json:"jti"`
	Nonce          string               `json:"nonce"`
	OrganizationID string               `json:"coh_org_id"`
	ActorID        string               `json:"coh_actor_id"`
	Roles          []localidentity.Role `json:"coh_roles"`
	TenantIDs      []string             `json:"coh_tenant_ids"`
}
