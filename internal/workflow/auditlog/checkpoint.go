package auditlog

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *Service) checkpointFor(ctx context.Context, head tamperaudit.Head, record tamperaudit.Record, now time.Time) (*tamperaudit.Checkpoint, error) {
	sequence, chainHash, reason := checkpointTarget(head, record, now)
	if reason == "" {
		return nil, nil
	}
	checkpointID, err := service.ids.NewAuditID(now)
	if err != nil {
		return nil, ErrUnavailable
	}
	draft := tamperaudit.Checkpoint{SchemaVersion: tamperaudit.CheckpointSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion, CheckpointID: checkpointID,
		OrganizationID: record.OrganizationID, TenantID: record.TenantID,
		CoveredFromSequence: head.LastCheckpointSequence + 1, Sequence: sequence,
		RecordCount: sequence - head.LastCheckpointSequence, ChainHash: chainHash,
		Reason: reason, CreatedAt: formatTime(now)}
	signed, err := service.signer.SignAuditCheckpoint(ctx, draft)
	if err != nil || !sameCheckpointDraft(draft, signed) {
		return nil, ErrUnavailable
	}
	authority, err := service.resolver.ResolveAuditKey(ctx, signed.SigningKeyID, signed.SigningKeyRevision)
	if err != nil || !validAuthority(authority, signed, now) || tamperaudit.VerifyCheckpoint(signed, authority.PublicKey) != nil {
		return nil, ErrUnavailable
	}
	return &signed, nil
}

func checkpointTarget(head tamperaudit.Head, record tamperaudit.Record, now time.Time) (uint64, string, string) {
	if head.Sequence > head.LastCheckpointSequence && crossedUTCDate(head.LastRecordAt, now) {
		return head.Sequence, head.ChainHash, "daily"
	}
	if record.Sequence-head.LastCheckpointSequence >= tamperaudit.CheckpointRecordLimit {
		return record.Sequence, record.ChainHash, "record_limit"
	}
	return 0, "", ""
}

func crossedUTCDate(lastRecordAt string, now time.Time) bool {
	last := mustTime(lastRecordAt)
	if last.IsZero() {
		return false
	}
	year, month, day := last.UTC().Date()
	otherYear, otherMonth, otherDay := now.UTC().Date()
	return year != otherYear || month != otherMonth || day != otherDay
}

func sameCheckpointDraft(draft, signed tamperaudit.Checkpoint) bool {
	draft.SigningKeyID, draft.SigningKeyRevision = signed.SigningKeyID, signed.SigningKeyRevision
	draft.SignatureAlgorithm, draft.Signature = signed.SignatureAlgorithm, signed.Signature
	left, leftErr := tamperaudit.CanonicalCheckpoint(draft)
	right, rightErr := tamperaudit.CanonicalCheckpoint(signed)
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(left, right) == 1
}

func validAuthority(authority KeyAuthority, checkpoint tamperaudit.Checkpoint, now time.Time) bool {
	created := mustTime(checkpoint.CreatedAt)
	if authority.KeyID != checkpoint.SigningKeyID || authority.Revision != checkpoint.SigningKeyRevision ||
		len(authority.PublicKey) == 0 || authority.ValidFrom.IsZero() || authority.ValidUntil.IsZero() ||
		created.Before(authority.ValidFrom) || !created.Before(authority.ValidUntil) || now.Before(created) {
		return false
	}
	return authority.RevokedAt == nil || created.Before(authority.RevokedAt.UTC())
}
