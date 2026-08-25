// Package credentiallease defines the non-secret contract and decisions for
// broker-owned, short-lived credential leases.
package credentiallease

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

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

// IssuanceAuthority is trusted input from authenticated broker boundaries. A
// request cannot create or alter these facts.
type IssuanceAuthority struct {
	Context                     secretref.Context
	Active                      bool
	ActorRevision               uint64
	AuthorizationAllowed        bool
	AuthorizationDecisionDigest string
	PolicyAllowed               bool
	PolicyDecisionDigest        string
	ApprovalRequired            bool
	ApprovalAllowed             bool
	ApprovalDecisionDigest      string
	Audience                    AudienceAuthority
}

type AudienceAuthority struct {
	Audience
	Active     bool
	Revision   uint64
	Remote     bool
	MutualTLS  bool
	ObservedAt time.Time
}

// DispatchRequest is the actual adapter scope presented for one credential
// use. It must exactly equal the immutable issuance scope.
type DispatchRequest struct {
	Context       secretref.Context
	TaskID        string
	ActionDigest  string
	TargetDigests []string
	Operation     string
	Audience      Audience
}

// DispatchAuthority is a fresh trusted snapshot. Rotation, revocation,
// cancellation, E-stop, or any changed decision invalidates the lease.
type DispatchAuthority struct {
	IssuanceAuthority
	TaskActive          bool
	EmergencyStopActive bool
}

type RevocationRequest struct {
	LeaseID string
	Reason  string
}
