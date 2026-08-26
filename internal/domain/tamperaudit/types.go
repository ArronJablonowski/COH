// Package tamperaudit defines COH's canonical, tenant-scoped audit chain.
// It contains pure validation and cryptographic operations; durable append and
// key custody remain adapter responsibilities.
package tamperaudit

const (
	EventSchemaVersion      = "coh.audit-event/v1"
	RecordSchemaVersion     = "coh.audit-record/v1"
	CheckpointSchemaVersion = "coh.audit-checkpoint/v1"
	ContractVersion         = "1.0.0"
	SignatureAlgorithm      = "ed25519"
	RecordHashDomain        = "COH-AUDIT-RECORD-V1\x00"
	CheckpointDomain        = "COH-AUDIT-CHECKPOINT-V1\x00"
	GenesisHash             = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	CheckpointRecordLimit   = uint64(10_000)
	// OrganizationAuditTenantID is the reserved chain for events, such as
	// login, that occur before a concrete tenant has been established.
	OrganizationAuditTenantID = "00000000-0000-7000-8000-000000000000"
)

// Event is the bounded, redacted event shape admitted to the durable chain.
// Raw requests, policy source, evidence, credentials, and free-form text have
// no field in this contract.
type Event struct {
	SchemaVersion   string   `json:"schema_version"`
	ContractVersion string   `json:"contract_version"`
	EventID         string   `json:"event_id"`
	OrganizationID  string   `json:"organization_id"`
	TenantID        string   `json:"tenant_id"`
	CaseID          string   `json:"case_id,omitempty"`
	ActorID         string   `json:"actor_id,omitempty"`
	ActorRevision   uint64   `json:"actor_revision,omitempty"`
	SourceSchema    string   `json:"source_schema"`
	Operation       string   `json:"operation"`
	Outcome         string   `json:"outcome"`
	ReasonCode      string   `json:"reason_code"`
	SubjectID       string   `json:"subject_id,omitempty"`
	SubjectRevision uint64   `json:"subject_revision,omitempty"`
	SubjectDigest   string   `json:"subject_digest,omitempty"`
	EvidenceDigests []string `json:"evidence_digests"`
	OccurredAt      string   `json:"occurred_at,omitempty"`
}

// Record is one immutable link. EventDigest permits bounded verification
// before hashing the complete record preimage.
type Record struct {
	SchemaVersion     string `json:"schema_version"`
	ContractVersion   string `json:"contract_version"`
	OrganizationID    string `json:"organization_id"`
	TenantID          string `json:"tenant_id"`
	Sequence          uint64 `json:"sequence"`
	Event             Event  `json:"event"`
	EventDigest       string `json:"event_digest"`
	PreviousChainHash string `json:"previous_chain_hash"`
	ChainHash         string `json:"chain_hash"`
	AppendedAt        string `json:"appended_at"`
}

// Checkpoint signs one exact tenant chain head. CoveredFromSequence is one
// greater than the prior checkpoint sequence (or one for the first).
type Checkpoint struct {
	SchemaVersion       string `json:"schema_version"`
	ContractVersion     string `json:"contract_version"`
	CheckpointID        string `json:"checkpoint_id"`
	OrganizationID      string `json:"organization_id"`
	TenantID            string `json:"tenant_id"`
	CoveredFromSequence uint64 `json:"covered_from_sequence"`
	Sequence            uint64 `json:"sequence"`
	RecordCount         uint64 `json:"record_count"`
	ChainHash           string `json:"chain_hash"`
	Reason              string `json:"reason"`
	SigningKeyID        string `json:"signing_key_id"`
	SigningKeyRevision  uint64 `json:"signing_key_revision"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	CreatedAt           string `json:"created_at"`
	Signature           string `json:"signature"`
}

// Head is the minimum state required for optimistic append and checkpoint
// scheduling. An empty chain has Sequence zero and GenesisHash.
type Head struct {
	OrganizationID         string
	TenantID               string
	Sequence               uint64
	ChainHash              string
	LastRecordAt           string
	LastCheckpointSequence uint64
	LastCheckpointAt       string
}
