package custody

import "github.com/ArronJablonowski/COH/internal/domain"

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type evidenceWire struct {
	Artifact                 artifactWire `json:"artifact"`
	Manifest                 artifactWire `json:"manifest"`
	ManifestProvenanceDigest string       `json:"manifest_provenance_digest"`
	IngestionReceiptDigest   string       `json:"ingestion_receipt_digest"`
}

type headWire struct {
	Case         caseWire `json:"case"`
	Sequence     uint64   `json:"sequence"`
	ChainHash    string   `json:"chain_hash"`
	LastRecordAt *string  `json:"last_record_at"`
}

type commandWire struct {
	SchemaVersion            string         `json:"schema_version"`
	ContractVersion          string         `json:"contract_version"`
	RequestID                string         `json:"request_id"`
	IdempotencyKey           string         `json:"idempotency_key"`
	Operation                Operation      `json:"operation"`
	Phase                    Phase          `json:"phase"`
	Case                     caseWire       `json:"case"`
	ActorID                  string         `json:"actor_id"`
	ActorRevision            uint64         `json:"actor_revision"`
	Subject                  evidenceWire   `json:"subject"`
	Parents                  []evidenceWire `json:"parents"`
	SourceIdentityDigest     *string        `json:"source_identity_digest"`
	PurposeDigest            *string        `json:"purpose_digest"`
	DestinationDigest        *string        `json:"destination_digest"`
	RecipientDigest          *string        `json:"recipient_digest"`
	TransformationDigest     *string        `json:"transformation_digest"`
	RuleDigest               *string        `json:"rule_digest"`
	ReasonDigest             *string        `json:"reason_digest"`
	MappingDigest            *string        `json:"mapping_digest"`
	ApprovalDigest           *string        `json:"approval_digest"`
	GoverningDecisionDigest  *string        `json:"governing_decision_digest"`
	ExternalReceiptDigest    *string        `json:"external_receipt_digest"`
	LifecycleReceiptDigest   *string        `json:"lifecycle_receipt_digest"`
	PriorAuthorizationDigest *string        `json:"prior_authorization_digest"`
	ArtifactSetDigest        *string        `json:"artifact_set_digest"`
	PolicyDigest             string         `json:"policy_digest"`
	ExpectedCaseRevision     uint64         `json:"expected_case_revision"`
	ExpectedHead             headWire       `json:"expected_head"`
	Deadline                 string         `json:"deadline"`
}

type authorizationWire struct {
	SchemaVersion          string      `json:"schema_version"`
	ContractVersion        string      `json:"contract_version"`
	AuthorizationDigest    string      `json:"authorization_digest"`
	IntentDigest           string      `json:"intent_digest"`
	Command                commandWire `json:"command"`
	CaseState              string      `json:"case_state"`
	CaseClassification     string      `json:"case_classification"`
	CaseRevision           uint64      `json:"case_revision"`
	RetentionPolicyDigest  string      `json:"retention_policy_digest"`
	RetainUntil            string      `json:"retain_until"`
	LegalHold              bool        `json:"legal_hold"`
	CaseProvenanceDigest   string      `json:"case_provenance_digest"`
	EvidenceVerifiedDigest string      `json:"evidence_verified_digest"`
	CurrentHead            headWire    `json:"current_head"`
}

type decisionWire struct {
	SchemaVersion        string          `json:"schema_version"`
	ContractVersion      string          `json:"contract_version"`
	DecisionID           string          `json:"decision_id"`
	DecisionDigest       string          `json:"decision_digest"`
	AuthorizationDigest  string          `json:"authorization_digest"`
	IntentDigest         string          `json:"intent_digest"`
	Operation            Operation       `json:"operation"`
	Phase                Phase           `json:"phase"`
	Case                 caseWire        `json:"case"`
	ActorID              string          `json:"actor_id"`
	ActorRevision        uint64          `json:"actor_revision"`
	ExpectedCaseRevision uint64          `json:"expected_case_revision"`
	ExpectedHead         headWire        `json:"expected_head"`
	PolicyDigest         string          `json:"policy_digest"`
	RevocationDigest     string          `json:"revocation_digest"`
	Outcome              DecisionOutcome `json:"outcome"`
	ReasonCode           DecisionReason  `json:"reason_code"`
	IssuedAt             string          `json:"issued_at"`
	ExpiresAt            string          `json:"expires_at"`
	Revision             uint64          `json:"revision"`
}

type recordWire struct {
	SchemaVersion            string      `json:"schema_version"`
	ContractVersion          string      `json:"contract_version"`
	CustodyID                string      `json:"custody_id"`
	Case                     caseWire    `json:"case"`
	Sequence                 uint64      `json:"sequence"`
	PreviousChainHash        string      `json:"previous_chain_hash"`
	Command                  commandWire `json:"command"`
	IntentDigest             string      `json:"intent_digest"`
	AuthorizationDigest      string      `json:"authorization_digest"`
	DecisionDigest           string      `json:"decision_digest"`
	RevocationDigest         string      `json:"revocation_digest"`
	EvidenceVerifiedDigest   string      `json:"evidence_verified_digest"`
	PreviousProvenanceDigest *string     `json:"previous_provenance_digest"`
	ProvenanceDigest         string      `json:"provenance_digest"`
	AuditEventDigest         string      `json:"audit_event_digest"`
	OccurredAt               string      `json:"occurred_at"`
	RecordDigest             string      `json:"record_digest"`
	ChainHash                string      `json:"chain_hash"`
}

type receiptWire struct {
	SchemaVersion     string   `json:"schema_version"`
	ContractVersion   string   `json:"contract_version"`
	RequestID         string   `json:"request_id"`
	Case              caseWire `json:"case"`
	IdempotencyDigest string   `json:"idempotency_digest"`
	IntentDigest      string   `json:"intent_digest"`
	DecisionDigest    string   `json:"decision_digest"`
	CustodyID         string   `json:"custody_id"`
	Sequence          uint64   `json:"sequence"`
	RecordDigest      string   `json:"record_digest"`
	ChainHash         string   `json:"chain_hash"`
	AuditEventDigest  string   `json:"audit_event_digest"`
	ProvenanceDigest  string   `json:"provenance_digest"`
	CreatedAt         string   `json:"created_at"`
	ReceiptDigest     string   `json:"receipt_digest"`
}

type verificationWire struct {
	SchemaVersion         string              `json:"schema_version"`
	ContractVersion       string              `json:"contract_version"`
	Case                  caseWire            `json:"case"`
	FromSequence          uint64              `json:"from_sequence"`
	ToSequence            uint64              `json:"to_sequence"`
	HeadChainHash         string              `json:"head_chain_hash"`
	AuditCheckpointID     *string             `json:"audit_checkpoint_id"`
	AuditCheckpointDigest *string             `json:"audit_checkpoint_digest"`
	Outcome               VerificationOutcome `json:"outcome"`
	ReasonCode            VerificationReason  `json:"reason_code"`
	VerifiedAt            string              `json:"verified_at"`
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{value.OrganizationID, value.TenantID, value.CaseID}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{value.Digest, value.MediaType, value.Classification, value.Length}
}

func evidenceToWire(value EvidenceReference) evidenceWire {
	return evidenceWire{artifactToWire(value.Artifact), artifactToWire(value.Manifest),
		value.ManifestProvenanceDigest, value.IngestionReceiptDigest}
}

func evidenceSliceToWire(values []EvidenceReference) []evidenceWire {
	result := make([]evidenceWire, len(values))
	for index, value := range values {
		result[index] = evidenceToWire(value)
	}
	return result
}

func headToWire(value Head) headWire {
	var last *string
	if value.LastRecordAt != nil {
		formatted := formatTime(*value.LastRecordAt)
		last = &formatted
	}
	return headWire{caseToWire(value.Case), value.Sequence, value.ChainHash, last}
}

func commandToWire(value Command) commandWire {
	return commandWire{value.SchemaVersion, value.ContractVersion, value.RequestID, value.IdempotencyKey,
		value.Operation, value.Phase, caseToWire(value.Case), value.ActorID, value.ActorRevision,
		evidenceToWire(value.Subject), evidenceSliceToWire(value.Parents), clonePointer(value.SourceIdentityDigest),
		clonePointer(value.PurposeDigest), clonePointer(value.DestinationDigest), clonePointer(value.RecipientDigest),
		clonePointer(value.TransformationDigest), clonePointer(value.RuleDigest), clonePointer(value.ReasonDigest),
		clonePointer(value.MappingDigest), clonePointer(value.ApprovalDigest), clonePointer(value.GoverningDecisionDigest),
		clonePointer(value.ExternalReceiptDigest),
		clonePointer(value.LifecycleReceiptDigest), clonePointer(value.PriorAuthorizationDigest),
		clonePointer(value.ArtifactSetDigest), value.PolicyDigest, value.ExpectedCaseRevision,
		headToWire(value.ExpectedHead), formatTime(value.Deadline)}
}

func authorizationToWire(value AuthorizationRequest) authorizationWire {
	return authorizationWire{value.SchemaVersion, value.ContractVersion, value.AuthorizationDigest,
		value.IntentDigest, commandToWire(value.Command), value.CaseState, value.CaseClassification,
		value.CaseRevision, value.RetentionPolicyDigest, formatTime(value.RetainUntil), value.LegalHold,
		value.CaseProvenanceDigest, value.EvidenceVerifiedDigest, headToWire(value.CurrentHead)}
}

func decisionToWire(value Decision) decisionWire {
	return decisionWire{value.SchemaVersion, value.ContractVersion, value.DecisionID, value.DecisionDigest,
		value.AuthorizationDigest, value.IntentDigest, value.Operation, value.Phase, caseToWire(value.Case),
		value.ActorID, value.ActorRevision, value.ExpectedCaseRevision, headToWire(value.ExpectedHead),
		value.PolicyDigest, value.RevocationDigest, value.Outcome, value.ReasonCode, formatTime(value.IssuedAt),
		formatTime(value.ExpiresAt), value.Revision}
}

func recordToWire(value Record) recordWire {
	return recordWire{value.SchemaVersion, value.ContractVersion, value.CustodyID, caseToWire(value.Case),
		value.Sequence, value.PreviousChainHash, commandToWire(value.Command), value.IntentDigest,
		value.AuthorizationDigest, value.DecisionDigest, value.RevocationDigest, value.EvidenceVerifiedDigest,
		clonePointer(value.PreviousProvenanceDigest), value.ProvenanceDigest, value.AuditEventDigest,
		formatTime(value.OccurredAt), value.RecordDigest, value.ChainHash}
}

func receiptToWire(value Receipt) receiptWire {
	return receiptWire{value.SchemaVersion, value.ContractVersion, value.RequestID, caseToWire(value.Case),
		value.IdempotencyDigest, value.IntentDigest, value.DecisionDigest, value.CustodyID, value.Sequence,
		value.RecordDigest, value.ChainHash, value.AuditEventDigest, value.ProvenanceDigest,
		formatTime(value.CreatedAt), value.ReceiptDigest}
}

func verificationToWire(value VerificationReport) verificationWire {
	return verificationWire{value.SchemaVersion, value.ContractVersion, caseToWire(value.Case),
		value.FromSequence, value.ToSequence, value.HeadChainHash, clonePointer(value.AuditCheckpointID),
		clonePointer(value.AuditCheckpointDigest), value.Outcome, value.ReasonCode, formatTime(value.VerifiedAt)}
}
