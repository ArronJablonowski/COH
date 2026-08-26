// Package approvallifecycle defines the durable approval state machine contract.
// Broker composition owns authority checks and persistence side effects.
package approvallifecycle

const (
	SchemaVersion   = "coh.approval-lifecycle/v2"
	ContractVersion = "2.0.0"
)

type State string

const (
	Requested State = "requested"
	Granted   State = "granted"
	Rejected  State = "rejected"
	Expired   State = "expired"
	Consumed  State = "consumed"
	Revoked   State = "revoked"
)

// Grant is one distinct approver's durable decision. ActorRevision binds the
// decision to the fresh identity authority used by the broker.
type Grant struct {
	ActorID            string `json:"actor_id"`
	ActorRevision      uint64 `json:"actor_revision"`
	PrincipalID        string `json:"principal_id"`
	EnrollmentRevision uint64 `json:"enrollment_revision"`
	GrantedAt          string `json:"granted_at"`
}

// Record is the complete safe-to-persist approval authority. It contains only
// identifiers, digests, bounded reason codes, counters, and timestamps.
type Record struct {
	SchemaVersion        string  `json:"schema_version"`
	ContractVersion      string  `json:"contract_version"`
	ApprovalID           string  `json:"approval_id"`
	OrganizationID       string  `json:"organization_id"`
	TenantID             string  `json:"tenant_id"`
	CaseID               string  `json:"case_id"`
	FingerprintDigest    string  `json:"fingerprint_digest"`
	ManifestDigest       string  `json:"manifest_digest"`
	PolicyDecisionDigest string  `json:"policy_decision_digest"`
	RequestorActorID     string  `json:"requestor_actor_id"`
	RequestorRevision    uint64  `json:"requestor_revision"`
	RequestorPrincipalID string  `json:"requestor_principal_id"`
	ActionOwnerActorID   string  `json:"action_owner_actor_id"`
	ActionTier           string  `json:"action_tier"`
	State                State   `json:"state"`
	Revision             uint64  `json:"revision"`
	RequestedAt          string  `json:"requested_at"`
	ValidFrom            string  `json:"valid_from"`
	ValidUntil           string  `json:"valid_until"`
	RequiredGrantCount   uint8   `json:"required_grant_count"`
	Grants               []Grant `json:"grants"`
	MaximumUseCount      uint32  `json:"maximum_use_count"`
	UseCount             uint32  `json:"use_count"`
	ReasonCode           string  `json:"reason_code"`
	LastActorID          string  `json:"last_actor_id"`
	LastActorRevision    uint64  `json:"last_actor_revision"`
	LastOperationDigest  string  `json:"last_operation_digest"`
	LastEventID          string  `json:"last_event_id"`
	UpdatedAt            string  `json:"updated_at"`
}

// Event is safe audit input for both committed and denied lifecycle attempts.
type Event struct {
	SchemaVersion     string `json:"schema_version"`
	ContractVersion   string `json:"contract_version"`
	EventID           string `json:"event_id"`
	Operation         string `json:"operation"`
	Outcome           string `json:"outcome"`
	ReasonCode        string `json:"reason_code"`
	ApprovalID        string `json:"approval_id,omitempty"`
	OrganizationID    string `json:"organization_id,omitempty"`
	TenantID          string `json:"tenant_id,omitempty"`
	CaseID            string `json:"case_id,omitempty"`
	FingerprintDigest string `json:"fingerprint_digest,omitempty"`
	ActorID           string `json:"actor_id,omitempty"`
	ActorRevision     uint64 `json:"actor_revision,omitempty"`
	RecordRevision    uint64 `json:"record_revision,omitempty"`
	OccurredAt        string `json:"occurred_at"`
}
