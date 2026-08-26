package auditlog

import (
	"crypto/subtle"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

// ValidateCommit independently proves the complete append/checkpoint shape so
// every persistence adapter enforces identical fail-closed invariants.
func ValidateCommit(commit Commit) error {
	record := commit.Record
	if commit.IdempotencyKey == "" || commit.IdempotencyKey != record.Event.EventID ||
		commit.RequestDigest != record.EventDigest || tamperaudit.ValidateRecord(record) != nil {
		return ErrInvalidInput
	}
	expected := commit.ExpectedHead
	previousHash := expected.ChainHash
	if expected.Sequence == 0 && previousHash == "" {
		previousHash = tamperaudit.GenesisHash
	}
	if expected.Sequence > 0 && validateHead(expected, record.OrganizationID, record.TenantID) != nil ||
		record.Sequence != expected.Sequence+1 || tamperaudit.VerifyRecord(record, record.Sequence, previousHash) != nil {
		return ErrIntegrity
	}
	checkpointRequiredDaily := expected.Sequence > expected.LastCheckpointSequence && crossedUTCDate(expected.LastRecordAt, mustTime(record.AppendedAt))
	checkpointRequiredLimit := record.Sequence-expected.LastCheckpointSequence >= tamperaudit.CheckpointRecordLimit
	if commit.Checkpoint == nil {
		if checkpointRequiredDaily || checkpointRequiredLimit {
			return ErrIntegrity
		}
		return nil
	}
	checkpoint := *commit.Checkpoint
	if tamperaudit.ValidateCheckpoint(checkpoint) != nil || checkpoint.OrganizationID != record.OrganizationID ||
		checkpoint.TenantID != record.TenantID || checkpoint.CoveredFromSequence != expected.LastCheckpointSequence+1 {
		return ErrIntegrity
	}
	switch checkpoint.Reason {
	case "daily":
		if !checkpointRequiredDaily || checkpoint.Sequence != expected.Sequence ||
			subtle.ConstantTimeCompare([]byte(checkpoint.ChainHash), []byte(previousHash)) != 1 {
			return ErrIntegrity
		}
	case "record_limit":
		if checkpointRequiredDaily || !checkpointRequiredLimit || checkpoint.Sequence != record.Sequence ||
			checkpoint.RecordCount != tamperaudit.CheckpointRecordLimit ||
			subtle.ConstantTimeCompare([]byte(checkpoint.ChainHash), []byte(record.ChainHash)) != 1 {
			return ErrIntegrity
		}
	case "manual_final":
		if checkpointRequiredDaily || checkpointRequiredLimit || checkpoint.Sequence != record.Sequence ||
			subtle.ConstantTimeCompare([]byte(checkpoint.ChainHash), []byte(record.ChainHash)) != 1 {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	return nil
}
