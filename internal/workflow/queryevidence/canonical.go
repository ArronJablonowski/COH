package queryevidence

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	recordDigestDomain     = "COH-QUERY-EVIDENCE-RECORD-V1\x00"
	provenanceDigestDomain = "COH-QUERY-EVIDENCE-PROVENANCE-V1\x00"
	transitionDigestDomain = "COH-QUERY-EVIDENCE-TRANSITION-V1\x00"
	auditDigestDomain      = "COH-QUERY-EVIDENCE-AUDIT-V1\x00"
	timestampLayout        = "2006-01-02T15:04:05.000000000Z"
)

func canonicalDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Internal, "canonicalization_failed", err)
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func FinalizeRecord(value Record) (Record, error) {
	value.RecordDigest, value.ProvenanceDigest, value.TransitionID = "", "", ""
	if err := validateRecord(value, true); err != nil {
		return Record{}, err
	}
	transition, err := canonicalDigest(transitionDigestDomain, value)
	if err != nil {
		return Record{}, err
	}
	value.TransitionID = transition
	provenance, err := canonicalDigest(provenanceDigestDomain, value)
	if err != nil {
		return Record{}, err
	}
	value.ProvenanceDigest = provenance
	recordDigest, err := canonicalDigest(recordDigestDomain, value)
	if err != nil {
		return Record{}, err
	}
	value.RecordDigest = recordDigest
	return value, nil
}

func VerifyRecord(value Record) error {
	suppliedRecord, suppliedProvenance, suppliedTransition := value.RecordDigest, value.ProvenanceDigest, value.TransitionID
	value.RecordDigest, value.ProvenanceDigest, value.TransitionID = "", "", ""
	finalized, err := FinalizeRecord(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(suppliedRecord), []byte(finalized.RecordDigest)) != 1 ||
		subtle.ConstantTimeCompare([]byte(suppliedProvenance), []byte(finalized.ProvenanceDigest)) != 1 ||
		subtle.ConstantTimeCompare([]byte(suppliedTransition), []byte(finalized.TransitionID)) != 1 {
		return newError(Conflict, "record_integrity", err)
	}
	return nil
}

func finalizeAudit(value AuditEvent) (AuditEvent, error) {
	value.EventDigest = ""
	if err := validateAudit(value, true); err != nil {
		return AuditEvent{}, err
	}
	digest, err := canonicalDigest(auditDigestDomain, value)
	if err != nil {
		return AuditEvent{}, err
	}
	value.EventDigest = digest
	return value, nil
}
