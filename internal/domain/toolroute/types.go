// Package toolroute owns the strict broker-routing representation of the
// domain ToolIntent and ActionReceipt records.
package toolroute

import "github.com/ArronJablonowski/COH/internal/domain"

const (
	SchemaVersion   = "coh.tool-route/v1"
	ContractVersion = "1.0.0"
)

type IntentRecord struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	OperationID     string `json:"operation_id"`
	OrganizationID  string `json:"organization_id"`
	TenantID        string `json:"tenant_id"`
	CaseID          string `json:"case_id"`
	Tool            string `json:"tool"`
	Action          string `json:"action"`
	TargetDigest    string `json:"target_digest"`
	ArgumentDigest  string `json:"argument_digest"`
}

type ReceiptRecord struct {
	SchemaVersion          string `json:"schema_version"`
	ContractVersion        string `json:"contract_version"`
	IntentDigest           string `json:"intent_digest"`
	Outcome                string `json:"outcome"`
	EvidenceDigest         string `json:"evidence_digest"`
	EvidenceMediaType      string `json:"evidence_media_type"`
	EvidenceClassification string `json:"evidence_classification"`
	EvidenceLength         int64  `json:"evidence_length"`
}

type StateRecord struct {
	SchemaVersion              string `json:"schema_version"`
	ContractVersion            string `json:"contract_version"`
	RecordType                 string `json:"record_type"`
	OperationID                string `json:"operation_id"`
	OrganizationID             string `json:"organization_id"`
	TenantID                   string `json:"tenant_id"`
	CaseID                     string `json:"case_id"`
	IntentDigest               string `json:"intent_digest"`
	IdempotencyDigest          string `json:"idempotency_digest"`
	ContextDigest              string `json:"context_digest"`
	ManifestDigest             string `json:"manifest_digest"`
	IntentPolicyDecisionDigest string `json:"intent_policy_decision_digest"`
	PreDispatchDecisionDigest  string `json:"pre_dispatch_decision_digest"`
	ApprovalID                 string `json:"approval_id"`
	ApprovalRevision           uint64 `json:"approval_revision"`
	ApprovalFingerprintDigest  string `json:"approval_fingerprint_digest"`
	RequestorActorID           string `json:"requestor_actor_id"`
	RequestorActorRevision     uint64 `json:"requestor_actor_revision"`
	ActionOwnerActorID         string `json:"action_owner_actor_id"`
	ActionOwnerActorRevision   uint64 `json:"action_owner_actor_revision"`
	Status                     string `json:"status"`
	ReasonCode                 string `json:"reason_code"`
	DispatchAuditID            string `json:"dispatch_audit_id"`
	CompletionAuditID          string `json:"completion_audit_id"`
	ReceiptDigest              string `json:"receipt_digest"`
	PreviousProvenanceDigest   string `json:"previous_provenance_digest"`
	ProvenanceDigest           string `json:"provenance_digest"`
	CreatedAt                  string `json:"created_at"`
	UpdatedAt                  string `json:"updated_at"`
	Revision                   uint64 `json:"revision"`
}

func IntentFromDomain(value domain.ToolIntent) IntentRecord {
	return IntentRecord{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		OperationID: value.OperationID, OrganizationID: value.Case.OrganizationID,
		TenantID: value.Case.TenantID, CaseID: value.Case.CaseID, Tool: value.Tool,
		Action: value.Action, TargetDigest: value.TargetDigest, ArgumentDigest: value.ArgumentDigest}
}

func (value IntentRecord) Domain() domain.ToolIntent {
	return domain.ToolIntent{OperationID: value.OperationID,
		Case: domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID},
		Tool: value.Tool, Action: value.Action, TargetDigest: value.TargetDigest, ArgumentDigest: value.ArgumentDigest}
}

func ReceiptFromDomain(value domain.ActionReceipt) ReceiptRecord {
	return ReceiptRecord{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: value.IntentDigest, Outcome: value.Outcome, EvidenceDigest: value.Evidence.Digest,
		EvidenceMediaType: value.Evidence.MediaType, EvidenceClassification: value.Evidence.Classification,
		EvidenceLength: value.Evidence.Length}
}

func (value ReceiptRecord) Domain() domain.ActionReceipt {
	return domain.ActionReceipt{IntentDigest: value.IntentDigest, Outcome: value.Outcome,
		Evidence: domain.ArtifactRef{Digest: value.EvidenceDigest, MediaType: value.EvidenceMediaType,
			Classification: value.EvidenceClassification, Length: value.EvidenceLength}}
}
