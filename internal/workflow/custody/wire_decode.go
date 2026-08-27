package custody

import (
	"bytes"
	"encoding/json"
	"io"

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
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}

func evidenceSliceFromWire(values []evidenceWire) []EvidenceReference {
	result := make([]EvidenceReference, len(values))
	for index, value := range values {
		result[index] = evidenceFromWire(value)
	}
	return result
}

func headFromWire(value headWire) (Head, error) {
	result := Head{Case: caseFromWire(value.Case), Sequence: value.Sequence, ChainHash: value.ChainHash}
	if value.LastRecordAt != nil {
		parsed, err := parseTime(*value.LastRecordAt)
		if err != nil {
			return Head{}, err
		}
		result.LastRecordAt = &parsed
	}
	return result, nil
}

func commandFromWire(value commandWire) (Command, error) {
	head, err := headFromWire(value.ExpectedHead)
	if err != nil {
		return Command{}, err
	}
	deadline, err := parseTime(value.Deadline)
	if err != nil {
		return Command{}, err
	}
	return Command{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, IdempotencyKey: value.IdempotencyKey, Operation: value.Operation,
		Phase: value.Phase, Case: caseFromWire(value.Case), ActorID: value.ActorID,
		ActorRevision: value.ActorRevision, Subject: evidenceFromWire(value.Subject),
		Parents: evidenceSliceFromWire(value.Parents), SourceIdentityDigest: clonePointer(value.SourceIdentityDigest),
		PurposeDigest: clonePointer(value.PurposeDigest), DestinationDigest: clonePointer(value.DestinationDigest),
		RecipientDigest: clonePointer(value.RecipientDigest), TransformationDigest: clonePointer(value.TransformationDigest),
		RuleDigest: clonePointer(value.RuleDigest), ReasonDigest: clonePointer(value.ReasonDigest),
		MappingDigest: clonePointer(value.MappingDigest), ApprovalDigest: clonePointer(value.ApprovalDigest),
		ExternalReceiptDigest:    clonePointer(value.ExternalReceiptDigest),
		LifecycleReceiptDigest:   clonePointer(value.LifecycleReceiptDigest),
		PriorAuthorizationDigest: clonePointer(value.PriorAuthorizationDigest),
		ArtifactSetDigest:        clonePointer(value.ArtifactSetDigest), PolicyDigest: value.PolicyDigest,
		ExpectedCaseRevision: value.ExpectedCaseRevision, ExpectedHead: head, Deadline: deadline}, nil
}

func recordFromWire(value recordWire) (Record, error) {
	command, err := commandFromWire(value.Command)
	if err != nil {
		return Record{}, err
	}
	occurred, err := parseTime(value.OccurredAt)
	if err != nil {
		return Record{}, err
	}
	return Record{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CustodyID: value.CustodyID, Case: caseFromWire(value.Case), Sequence: value.Sequence,
		PreviousChainHash: value.PreviousChainHash, Command: command, IntentDigest: value.IntentDigest,
		AuthorizationDigest: value.AuthorizationDigest, DecisionDigest: value.DecisionDigest,
		RevocationDigest: value.RevocationDigest, EvidenceVerifiedDigest: value.EvidenceVerifiedDigest,
		PreviousProvenanceDigest: clonePointer(value.PreviousProvenanceDigest),
		ProvenanceDigest:         value.ProvenanceDigest, AuditEventDigest: value.AuditEventDigest,
		OccurredAt: occurred, RecordDigest: value.RecordDigest, ChainHash: value.ChainHash}, nil
}

func receiptFromWire(value receiptWire) (Receipt, error) {
	created, err := parseTime(value.CreatedAt)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		RequestID: value.RequestID, Case: caseFromWire(value.Case), IdempotencyDigest: value.IdempotencyDigest,
		IntentDigest: value.IntentDigest, DecisionDigest: value.DecisionDigest, CustodyID: value.CustodyID,
		Sequence: value.Sequence, RecordDigest: value.RecordDigest, ChainHash: value.ChainHash,
		AuditEventDigest: value.AuditEventDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: created, ReceiptDigest: value.ReceiptDigest}, nil
}

func decodeCanonical(data []byte, output any) error {
	if len(data) == 0 || len(data) > 1<<20 || !json.Valid(data) {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "record_encoding_invalid", false, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_encoding_invalid", false, err)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return newError(Denied, "record_noncanonical", false, err)
	}
	return nil
}
