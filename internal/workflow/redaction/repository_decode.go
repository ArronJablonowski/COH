package redaction

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactFromWire(value artifactWire) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func evidenceFromWire(value evidenceWire) EvidenceReference {
	return EvidenceReference{Artifact: artifactFromWire(value.Artifact), Manifest: artifactFromWire(value.Manifest),
		ManifestProvenanceDigest: value.ManifestProvenanceDigest, IngestionReceiptDigest: value.IngestionReceiptDigest}
}

func headFromWire(value headWire) (CustodyHead, error) {
	result := CustodyHead{Case: caseFromWire(value.Case), Sequence: value.Sequence, ChainHash: value.ChainHash}
	if value.LastRecordAt != nil {
		parsed, err := parseTime(*value.LastRecordAt)
		if err != nil {
			return CustodyHead{}, err
		}
		result.LastRecordAt = &parsed
	}
	return result, nil
}

func commandFromWire(value commandWire) (Command, error) {
	head, err := headFromWire(value.ExpectedCustodyHead)
	if err != nil {
		return Command{}, err
	}
	deadline, err := parseTime(value.Deadline)
	if err != nil {
		return Command{}, err
	}
	return Command{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Case: caseFromWire(value.Case),
		ActorID: value.ActorID, ActorRevision: value.ActorRevision, Source: evidenceFromWire(value.Source),
		RuleDigest: value.RuleDigest, PlanDigest: value.PlanDigest, ReasonDigest: value.ReasonDigest,
		OutputMediaType: value.OutputMediaType, OutputClassification: value.OutputClassification,
		KeyProfile: value.KeyProfile, KeyProfileDigest: value.KeyProfileDigest, PolicyDigest: value.PolicyDigest,
		ExpectedCaseRevision: value.ExpectedCaseRevision, ExpectedCustodyHead: head, Deadline: deadline}, nil
}

func mappingFromWire(value mappingWire) (Mapping, error) {
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Mapping{}, err
	}
	entries := make([]MappingEntry, len(value.Entries))
	for index, entry := range value.Entries {
		entries[index] = MappingEntry(entry)
	}
	return Mapping{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		MappingID: value.MappingID, Case: caseFromWire(value.Case), Source: evidenceFromWire(value.Source),
		DerivedArtifact: artifactFromWire(value.DerivedArtifact), PlanDigest: value.PlanDigest,
		RuleDigest: value.RuleDigest, ReasonDigest: value.ReasonDigest,
		ApprovalFingerprintDigest: value.ApprovalFingerprintDigest, Entries: entries, CreatedAt: created,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		MappingDigest: value.MappingDigest}, nil
}

func recordFromWire(value recordWire) (Record, error) {
	command, err := commandFromWire(value.Command)
	if err != nil {
		return Record{}, err
	}
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	return Record{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RedactionID: value.RedactionID, Case: caseFromWire(value.Case), Command: command,
		IntentDigest: value.IntentDigest, PlanDigest: value.PlanDigest, DecisionDigest: value.DecisionDigest,
		RevocationDigest: value.RevocationDigest, ApprovalUseDigest: value.ApprovalUseDigest,
		SourceVerificationDigest: value.SourceVerificationDigest, Derived: evidenceFromWire(value.Derived),
		DerivedIngestionReceiptDigest: value.DerivedIngestionReceiptDigest,
		MappingReference:              evidenceFromWire(value.MappingReference), MappingDigest: value.MappingDigest,
		MappingIngestionReceiptDigest: value.MappingIngestionReceiptDigest,
		CustodyReceiptDigest:          value.CustodyReceiptDigest, AuditEventDigest: value.AuditEventDigest,
		CreatedAt: created, PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		ProvenanceDigest: value.ProvenanceDigest, RecordDigest: value.RecordDigest}, nil
}

func receiptFromWire(value receiptWire) (Receipt, error) {
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, Case: caseFromWire(value.Case), IdempotencyDigest: value.IdempotencyDigest,
		IntentDigest: value.IntentDigest, RedactionID: value.RedactionID, RecordDigest: value.RecordDigest,
		Derived: evidenceFromWire(value.Derived), MappingReference: evidenceFromWire(value.MappingReference),
		MappingDigest: value.MappingDigest, CustodyReceiptDigest: value.CustodyReceiptDigest,
		AuditEventDigest: value.AuditEventDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: created, ReceiptDigest: value.ReceiptDigest}, nil
}

func publishedFromWire(value *publishedEvidenceWire) *PublishedEvidence {
	if value == nil {
		return nil
	}
	return &PublishedEvidence{Reference: evidenceFromWire(value.Reference), ReceiptDigest: value.ReceiptDigest}
}

func custodyProofFromWire(value *custodyProofWire) *CustodyProof {
	if value == nil {
		return nil
	}
	return &CustodyProof{ReceiptDigest: value.ReceiptDigest, RecordDigest: value.RecordDigest,
		ChainHash: value.ChainHash, Sequence: value.Sequence, AuditDigest: value.AuditDigest}
}

func progressFromWire(value progressWire) (Progress, error) {
	updated, err := parseTime(value.UpdatedAt)
	if err != nil {
		return Progress{}, err
	}
	return Progress{Case: caseFromWire(value.Case), IdempotencyDigest: value.IdempotencyDigest,
		IntentDigest: value.IntentDigest, Phase: value.Phase, Revision: value.Revision,
		PlanDigest: value.PlanDigest, DecisionDigest: value.DecisionDigest,
		ApprovalUseDigest: value.ApprovalUseDigest, Derived: publishedFromWire(value.Derived),
		Mapping: publishedFromWire(value.Mapping), MappingDigest: clonePointer(value.MappingDigest),
		Custody: custodyProofFromWire(value.Custody), UpdatedAt: updated}, nil
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "record_time_invalid", false, err)
	}
	return parsed, nil
}
