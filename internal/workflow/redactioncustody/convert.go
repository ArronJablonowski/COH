package redactioncustody

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

func custodyCommand(request redaction.CustodyRequest) (custody.Command, error) {
	rule, reason := request.Command.RuleDigest, request.Command.ReasonDigest
	mapping, approval, governing := request.MappingDigest, request.ApprovalDigest, request.DecisionDigest
	command := custody.Command{SchemaVersion: custody.CommandSchemaVersion, ContractVersion: custody.ContractVersion,
		RequestID:      deterministicUUID("COH-REDACTION-CUSTODY-ID-V1\x00", request.Command.RequestID),
		IdempotencyKey: boundedIdempotency(request.Command.IdempotencyKey), Operation: custody.Redact, Phase: custody.Completed,
		Case: request.Command.Case, ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		Subject: toCustodyEvidence(request.Derived), Parents: []custody.EvidenceReference{toCustodyEvidence(request.Command.Source)},
		RuleDigest: &rule, ReasonDigest: &reason, MappingDigest: &mapping, ApprovalDigest: &approval,
		GoverningDecisionDigest: &governing, PolicyDigest: request.Command.PolicyDigest,
		ExpectedCaseRevision: request.Command.ExpectedCaseRevision, ExpectedHead: toCustodyHead(request.ExpectedHead),
		Deadline: request.Deadline}
	if _, err := custody.CanonicalCommand(command); err != nil {
		return custody.Command{}, redactionError(redaction.InvalidInput, "custody_command_invalid", false)
	}
	return command, nil
}

func toCustodyEvidence(value redaction.EvidenceReference) custody.EvidenceReference {
	return custody.EvidenceReference{Artifact: value.Artifact, Manifest: value.Manifest,
		ManifestProvenanceDigest: value.ManifestProvenanceDigest, IngestionReceiptDigest: value.IngestionReceiptDigest}
}

func toCustodyHead(value redaction.CustodyHead) custody.Head {
	var last *time.Time
	if value.LastRecordAt != nil {
		copy := *value.LastRecordAt
		last = &copy
	}
	return custody.Head{Case: value.Case, Sequence: value.Sequence, ChainHash: value.ChainHash, LastRecordAt: last}
}

func toRedactionHead(value custody.Head) redaction.CustodyHead {
	var last *time.Time
	if value.LastRecordAt != nil {
		copy := *value.LastRecordAt
		last = &copy
	}
	return redaction.CustodyHead{Case: value.Case, Sequence: value.Sequence, ChainHash: value.ChainHash, LastRecordAt: last}
}

func toRedactionProof(value custody.Result) redaction.CustodyProof {
	return redaction.CustodyProof{ReceiptDigest: value.Receipt.ReceiptDigest, RecordDigest: value.Receipt.RecordDigest,
		ChainHash: value.Receipt.ChainHash, Sequence: value.Receipt.Sequence, AuditDigest: value.Receipt.AuditEventDigest}
}

func boundedIdempotency(value string) string {
	sum := sha256.Sum256([]byte("COH-REDACTION-CUSTODY-IDEMPOTENCY-V1\x00" + value))
	return "redaction-custody:" + hex.EncodeToString(sum[:])
}

func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func redactionError(code redaction.ErrorCode, reason string, retryable bool) error {
	return &redaction.Error{Code: code, Reason: reason, Retryable: retryable}
}

func translate(err error) error {
	switch custody.CodeOf(err) {
	case custody.InvalidInput:
		return redactionError(redaction.InvalidInput, custody.Reason(err), false)
	case custody.Denied:
		return redactionError(redaction.Denied, custody.Reason(err), false)
	case custody.NotFound:
		return redactionError(redaction.NotFound, custody.Reason(err), false)
	case custody.Conflict:
		return redactionError(redaction.Conflict, custody.Reason(err), custody.Retryable(err))
	case custody.Canceled:
		return redactionError(redaction.Canceled, custody.Reason(err), false)
	case custody.Timeout:
		return redactionError(redaction.Timeout, custody.Reason(err), custody.Retryable(err))
	case custody.InternalFailure:
		return redactionError(redaction.InternalFailure, custody.Reason(err), false)
	default:
		return redactionError(redaction.Unavailable, "custody_unavailable", true)
	}
}

var _ redaction.CustodyRecorder = (*Adapter)(nil)
