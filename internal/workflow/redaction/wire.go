package redaction

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
	SchemaVersion        string       `json:"schema_version"`
	ContractVersion      string       `json:"contract_version"`
	RequestID            string       `json:"request_id"`
	IdempotencyKey       string       `json:"idempotency_key"`
	Case                 caseWire     `json:"case"`
	ActorID              string       `json:"actor_id"`
	ActorRevision        uint64       `json:"actor_revision"`
	Source               evidenceWire `json:"source"`
	RuleDigest           string       `json:"rule_digest"`
	PlanDigest           string       `json:"plan_digest"`
	ReasonDigest         string       `json:"reason_digest"`
	OutputMediaType      string       `json:"output_media_type"`
	OutputClassification string       `json:"output_classification"`
	KeyProfile           string       `json:"key_profile"`
	KeyProfileDigest     string       `json:"key_profile_digest"`
	PolicyDigest         string       `json:"policy_digest"`
	ExpectedCaseRevision uint64       `json:"expected_case_revision"`
	ExpectedCustodyHead  headWire     `json:"expected_custody_head"`
	Deadline             string       `json:"deadline"`
}

type ruleWire struct {
	SchemaVersion        string            `json:"schema_version"`
	ContractVersion      string            `json:"contract_version"`
	RuleID               string            `json:"rule_id"`
	Revision             uint64            `json:"revision"`
	RuleDigest           string            `json:"rule_digest"`
	AllowedMediaTypes    []string          `json:"allowed_media_types"`
	PermittedModes       []ReplacementMode `json:"permitted_modes"`
	MaskDigest           *string           `json:"mask_digest"`
	TokenDigest          *string           `json:"token_digest"`
	MaximumSpans         uint16            `json:"maximum_spans"`
	MaximumSelectedBytes int64             `json:"maximum_selected_bytes"`
	MaximumOutputBytes   int64             `json:"maximum_output_bytes"`
	SignerKeyID          string            `json:"signer_key_id"`
	SignerKeyRevision    uint64            `json:"signer_key_revision"`
	Signature            string            `json:"signature"`
}

type spanWire struct {
	Ordinal             uint16          `json:"ordinal"`
	SourceStart         int64           `json:"source_start"`
	SourceEnd           int64           `json:"source_end"`
	SourceSegmentDigest string          `json:"source_segment_digest"`
	ReplacementMode     ReplacementMode `json:"replacement_mode"`
	ExpectedOutputStart int64           `json:"expected_output_start"`
	ExpectedOutputEnd   int64           `json:"expected_output_end"`
}

type planWire struct {
	SchemaVersion             string       `json:"schema_version"`
	ContractVersion           string       `json:"contract_version"`
	PlanID                    string       `json:"plan_id"`
	Case                      caseWire     `json:"case"`
	Source                    evidenceWire `json:"source"`
	RuleID                    string       `json:"rule_id"`
	RuleRevision              uint64       `json:"rule_revision"`
	RuleDigest                string       `json:"rule_digest"`
	ReasonDigest              string       `json:"reason_digest"`
	Spans                     []spanWire   `json:"spans"`
	MappingPlanDigest         string       `json:"mapping_plan_digest"`
	OutputMediaType           string       `json:"output_media_type"`
	OutputClassification      string       `json:"output_classification"`
	MaximumOutputBytes        int64        `json:"maximum_output_bytes"`
	ApprovalID                string       `json:"approval_id"`
	ApprovalFingerprintDigest string       `json:"approval_fingerprint_digest"`
	ApprovalManifestDigest    string       `json:"approval_manifest_digest"`
	PolicyDecisionDigest      string       `json:"policy_decision_digest"`
	PolicyDigest              string       `json:"policy_digest"`
	ValidFrom                 string       `json:"valid_from"`
	ValidUntil                string       `json:"valid_until"`
	PlanDigest                string       `json:"plan_digest"`
}

type mappingEntryWire struct {
	Ordinal             uint16          `json:"ordinal"`
	SourceStart         int64           `json:"source_start"`
	SourceEnd           int64           `json:"source_end"`
	SourceSegmentDigest string          `json:"source_segment_digest"`
	OutputStart         int64           `json:"output_start"`
	OutputEnd           int64           `json:"output_end"`
	ReplacementMode     ReplacementMode `json:"replacement_mode"`
	ReplacementDigest   string          `json:"replacement_digest"`
}

type mappingWire struct {
	SchemaVersion             string             `json:"schema_version"`
	ContractVersion           string             `json:"contract_version"`
	MappingID                 string             `json:"mapping_id"`
	Case                      caseWire           `json:"case"`
	Source                    evidenceWire       `json:"source"`
	DerivedArtifact           artifactWire       `json:"derived_artifact"`
	PlanDigest                string             `json:"plan_digest"`
	RuleDigest                string             `json:"rule_digest"`
	ReasonDigest              string             `json:"reason_digest"`
	ApprovalFingerprintDigest string             `json:"approval_fingerprint_digest"`
	Entries                   []mappingEntryWire `json:"entries"`
	CreatedAt                 string             `json:"created_at"`
	PreviousProvenanceDigest  string             `json:"previous_provenance_digest"`
	ProvenanceDigest          string             `json:"provenance_digest"`
	MappingDigest             string             `json:"mapping_digest"`
}

type approvalUseWire struct {
	ApprovalID           string `json:"approval_id"`
	FingerprintDigest    string `json:"fingerprint_digest"`
	ManifestDigest       string `json:"manifest_digest"`
	PolicyDecisionDigest string `json:"policy_decision_digest"`
	IntentDigest         string `json:"intent_digest"`
	State                string `json:"state"`
	Revision             uint64 `json:"revision"`
	UseCount             uint64 `json:"use_count"`
	MaximumUseCount      uint64 `json:"maximum_use_count"`
	ValidFrom            string `json:"valid_from"`
	ValidUntil           string `json:"valid_until"`
	UseDigest            string `json:"use_digest"`
	UsedAt               string `json:"used_at"`
	ProofDigest          string `json:"proof_digest"`
}

type authorizationWire struct {
	SchemaVersion            string          `json:"schema_version"`
	ContractVersion          string          `json:"contract_version"`
	AuthorizationDigest      string          `json:"authorization_digest"`
	IntentDigest             string          `json:"intent_digest"`
	Command                  commandWire     `json:"command"`
	Plan                     planWire        `json:"plan"`
	CaseState                string          `json:"case_state"`
	CaseClassification       string          `json:"case_classification"`
	CaseRevision             uint64          `json:"case_revision"`
	CaseProvenanceDigest     string          `json:"case_provenance_digest"`
	SourceVerificationDigest string          `json:"source_verification_digest"`
	ApprovalUse              approvalUseWire `json:"approval_use"`
	CurrentCustodyHead       headWire        `json:"current_custody_head"`
}

type decisionWire struct {
	SchemaVersion             string          `json:"schema_version"`
	ContractVersion           string          `json:"contract_version"`
	DecisionID                string          `json:"decision_id"`
	DecisionDigest            string          `json:"decision_digest"`
	AuthorizationDigest       string          `json:"authorization_digest"`
	IntentDigest              string          `json:"intent_digest"`
	Case                      caseWire        `json:"case"`
	ActorID                   string          `json:"actor_id"`
	ActorRevision             uint64          `json:"actor_revision"`
	SourceArtifactDigest      string          `json:"source_artifact_digest"`
	PlanDigest                string          `json:"plan_digest"`
	ApprovalFingerprintDigest string          `json:"approval_fingerprint_digest"`
	PolicyDigest              string          `json:"policy_digest"`
	RevocationDigest          string          `json:"revocation_digest"`
	ExpectedCaseRevision      uint64          `json:"expected_case_revision"`
	ExpectedCustodyHead       headWire        `json:"expected_custody_head"`
	Outcome                   DecisionOutcome `json:"outcome"`
	ReasonCode                DecisionReason  `json:"reason_code"`
	IssuedAt                  string          `json:"issued_at"`
	ExpiresAt                 string          `json:"expires_at"`
	Revision                  uint64          `json:"revision"`
}

type recordWire struct {
	SchemaVersion                 string       `json:"schema_version"`
	ContractVersion               string       `json:"contract_version"`
	RedactionID                   string       `json:"redaction_id"`
	Case                          caseWire     `json:"case"`
	Command                       commandWire  `json:"command"`
	IntentDigest                  string       `json:"intent_digest"`
	PlanDigest                    string       `json:"plan_digest"`
	DecisionDigest                string       `json:"decision_digest"`
	RevocationDigest              string       `json:"revocation_digest"`
	ApprovalUseDigest             string       `json:"approval_use_digest"`
	SourceVerificationDigest      string       `json:"source_verification_digest"`
	Derived                       evidenceWire `json:"derived"`
	DerivedIngestionReceiptDigest string       `json:"derived_ingestion_receipt_digest"`
	MappingReference              evidenceWire `json:"mapping_reference"`
	MappingDigest                 string       `json:"mapping_digest"`
	MappingIngestionReceiptDigest string       `json:"mapping_ingestion_receipt_digest"`
	CustodyReceiptDigest          string       `json:"custody_receipt_digest"`
	AuditEventDigest              string       `json:"audit_event_digest"`
	CreatedAt                     string       `json:"created_at"`
	PreviousProvenanceDigest      string       `json:"previous_provenance_digest"`
	ProvenanceDigest              string       `json:"provenance_digest"`
	RecordDigest                  string       `json:"record_digest"`
}

type receiptWire struct {
	SchemaVersion        string       `json:"schema_version"`
	ContractVersion      string       `json:"contract_version"`
	RequestID            string       `json:"request_id"`
	Case                 caseWire     `json:"case"`
	IdempotencyDigest    string       `json:"idempotency_digest"`
	IntentDigest         string       `json:"intent_digest"`
	RedactionID          string       `json:"redaction_id"`
	RecordDigest         string       `json:"record_digest"`
	Derived              evidenceWire `json:"derived"`
	MappingReference     evidenceWire `json:"mapping_reference"`
	MappingDigest        string       `json:"mapping_digest"`
	CustodyReceiptDigest string       `json:"custody_receipt_digest"`
	AuditEventDigest     string       `json:"audit_event_digest"`
	ProvenanceDigest     string       `json:"provenance_digest"`
	CreatedAt            string       `json:"created_at"`
	ReceiptDigest        string       `json:"receipt_digest"`
}

func caseToWire(v domain.CaseRef) caseWire { return caseWire{v.OrganizationID, v.TenantID, v.CaseID} }
func artifactToWire(v domain.ArtifactRef) artifactWire {
	return artifactWire{v.Digest, v.MediaType, v.Classification, v.Length}
}
func evidenceToWire(v EvidenceReference) evidenceWire {
	return evidenceWire{artifactToWire(v.Artifact), artifactToWire(v.Manifest), v.ManifestProvenanceDigest, v.IngestionReceiptDigest}
}
func headToWire(v CustodyHead) headWire {
	var last *string
	if v.LastRecordAt != nil {
		formatted := formatTime(*v.LastRecordAt)
		last = &formatted
	}
	return headWire{caseToWire(v.Case), v.Sequence, v.ChainHash, last}
}
func commandToWire(v Command) commandWire {
	return commandWire{v.SchemaVersion, v.ContractVersion, v.RequestID, v.IdempotencyKey, caseToWire(v.Case), v.ActorID,
		v.ActorRevision, evidenceToWire(v.Source), v.RuleDigest, v.PlanDigest, v.ReasonDigest, v.OutputMediaType,
		v.OutputClassification, v.KeyProfile, v.KeyProfileDigest, v.PolicyDigest, v.ExpectedCaseRevision,
		headToWire(v.ExpectedCustodyHead), formatTime(v.Deadline)}
}
func ruleToWire(v RuleSet) ruleWire {
	return ruleWire{v.SchemaVersion, v.ContractVersion, v.RuleID, v.Revision, v.RuleDigest,
		append([]string(nil), v.AllowedMediaTypes...), append([]ReplacementMode(nil), v.PermittedModes...),
		clonePointer(v.MaskDigest), clonePointer(v.TokenDigest), v.MaximumSpans, v.MaximumSelectedBytes, v.MaximumOutputBytes,
		v.SignerKeyID, v.SignerKeyRevision, v.Signature}
}
func spansToWire(values []PlanSpan) []spanWire {
	result := make([]spanWire, len(values))
	for i, v := range values {
		result[i] = spanWire{v.Ordinal, v.SourceStart,
			v.SourceEnd, v.SourceSegmentDigest, v.ReplacementMode, v.ExpectedOutputStart, v.ExpectedOutputEnd}
	}
	return result
}
func planToWire(v ApprovedPlan) planWire {
	return planWire{v.SchemaVersion, v.ContractVersion, v.PlanID, caseToWire(v.Case), evidenceToWire(v.Source), v.RuleID,
		v.RuleRevision, v.RuleDigest, v.ReasonDigest, spansToWire(v.Spans), v.MappingPlanDigest, v.OutputMediaType,
		v.OutputClassification, v.MaximumOutputBytes, v.ApprovalID, v.ApprovalFingerprintDigest, v.ApprovalManifestDigest,
		v.PolicyDecisionDigest, v.PolicyDigest, formatTime(v.ValidFrom), formatTime(v.ValidUntil), v.PlanDigest}
}
func entriesToWire(values []MappingEntry) []mappingEntryWire {
	result := make([]mappingEntryWire, len(values))
	for i, v := range values {
		result[i] = mappingEntryWire{v.Ordinal,
			v.SourceStart, v.SourceEnd, v.SourceSegmentDigest, v.OutputStart, v.OutputEnd, v.ReplacementMode, v.ReplacementDigest}
	}
	return result
}
func mappingToWire(v Mapping) mappingWire {
	return mappingWire{v.SchemaVersion, v.ContractVersion, v.MappingID, caseToWire(v.Case), evidenceToWire(v.Source),
		artifactToWire(v.DerivedArtifact), v.PlanDigest, v.RuleDigest, v.ReasonDigest, v.ApprovalFingerprintDigest,
		entriesToWire(v.Entries), formatTime(v.CreatedAt), v.PreviousProvenanceDigest, v.ProvenanceDigest, v.MappingDigest}
}
func approvalToWire(v ApprovalUseProof) approvalUseWire {
	return approvalUseWire{v.ApprovalID, v.FingerprintDigest, v.ManifestDigest, v.PolicyDecisionDigest, v.IntentDigest,
		v.State, v.Revision, v.UseCount, v.MaximumUseCount, formatTime(v.ValidFrom), formatTime(v.ValidUntil),
		v.UseDigest, formatTime(v.UsedAt), v.ProofDigest}
}
func authorizationToWire(v AuthorizationRequest) authorizationWire {
	return authorizationWire{v.SchemaVersion, v.ContractVersion, v.AuthorizationDigest, v.IntentDigest,
		commandToWire(v.Command), planToWire(v.Plan), v.CaseState, v.CaseClassification, v.CaseRevision,
		v.CaseProvenanceDigest, v.SourceVerificationDigest, approvalToWire(v.ApprovalUse), headToWire(v.CurrentCustodyHead)}
}
func decisionToWire(v Decision) decisionWire {
	return decisionWire{v.SchemaVersion, v.ContractVersion, v.DecisionID, v.DecisionDigest, v.AuthorizationDigest,
		v.IntentDigest, caseToWire(v.Case), v.ActorID, v.ActorRevision, v.SourceArtifactDigest, v.PlanDigest,
		v.ApprovalFingerprintDigest, v.PolicyDigest, v.RevocationDigest, v.ExpectedCaseRevision,
		headToWire(v.ExpectedCustodyHead), v.Outcome, v.ReasonCode, formatTime(v.IssuedAt), formatTime(v.ExpiresAt), v.Revision}
}
func recordToWire(v Record) recordWire {
	return recordWire{v.SchemaVersion, v.ContractVersion, v.RedactionID, caseToWire(v.Case), commandToWire(v.Command),
		v.IntentDigest, v.PlanDigest, v.DecisionDigest, v.RevocationDigest, v.ApprovalUseDigest,
		v.SourceVerificationDigest, evidenceToWire(v.Derived), v.DerivedIngestionReceiptDigest,
		evidenceToWire(v.MappingReference), v.MappingDigest, v.MappingIngestionReceiptDigest, v.CustodyReceiptDigest,
		v.AuditEventDigest, formatTime(v.CreatedAt), v.PreviousProvenanceDigest, v.ProvenanceDigest, v.RecordDigest}
}
func receiptToWire(v Receipt) receiptWire {
	return receiptWire{v.SchemaVersion, v.ContractVersion, v.RequestID, caseToWire(v.Case), v.IdempotencyDigest,
		v.IntentDigest, v.RedactionID, v.RecordDigest, evidenceToWire(v.Derived), evidenceToWire(v.MappingReference),
		v.MappingDigest, v.CustodyReceiptDigest, v.AuditEventDigest, v.ProvenanceDigest, formatTime(v.CreatedAt), v.ReceiptDigest}
}
