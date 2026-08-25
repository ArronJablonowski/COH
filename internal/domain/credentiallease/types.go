// Package credentiallease defines the non-secret contract and decisions for
// broker-owned, short-lived credential leases.
package credentiallease

import "github.com/ArronJablonowski/COH/internal/domain/secretref"

const (
	SchemaVersion     = "coh.credential-lease/v1"
	ContractVersion   = "1.0.0"
	MaximumTTLSeconds = uint32(300)
)

type IssuanceRequest struct {
	SchemaVersion       string              `json:"schema_version"`
	ContractVersion     string              `json:"contract_version"`
	RequestID           string              `json:"request_id"`
	IdempotencyKey      string              `json:"idempotency_key"`
	Context             secretref.Context   `json:"context"`
	TaskID              string              `json:"task_id"`
	ActionDigest        string              `json:"action_digest"`
	TargetDigests       []string            `json:"target_digests"`
	Operation           string              `json:"operation"`
	Audience            Audience            `json:"audience"`
	CredentialClass     string              `json:"credential_class"`
	Reference           secretref.Reference `json:"reference"`
	RequestedTTLSeconds uint32              `json:"requested_ttl_seconds"`
}

type Audience struct {
	Kind                    string `json:"kind"`
	ID                      string `json:"id"`
	TransportIdentityDigest string `json:"transport_identity_digest"`
}
