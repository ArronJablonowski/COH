package auditlog

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const maximumAppendAttempts = 4

func New(store Store, signer CheckpointSigner, resolver KeyResolver, clock Clock, ids IDSource) (*Service, error) {
	if store == nil || signer == nil || resolver == nil || clock == nil || ids == nil {
		return nil, ErrInvalidInput
	}
	return &Service{store: store, signer: signer, resolver: resolver, clock: clock, ids: ids}, nil
}

// Append accepts no caller-selected scope separate from the validated event.
// EventID is the immutable idempotency identity across crash recovery.
func (service *Service) Append(ctx context.Context, event tamperaudit.Event) (AppendResult, error) {
	if service == nil || service.store == nil || tamperaudit.ValidateEvent(event) != nil {
		return AppendResult{}, ErrInvalidInput
	}
	if ctx == nil || ctx.Err() != nil {
		return AppendResult{}, ErrUnavailable
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || event.OccurredAt != "" && now.Before(mustTime(event.OccurredAt)) {
		return AppendResult{}, ErrInvalidInput
	}
	for attempt := 0; attempt < maximumAppendAttempts; attempt++ {
		result, err := service.appendAtHead(ctx, event, now)
		if !errors.Is(err, ErrConflict) {
			return result, err
		}
	}
	return AppendResult{}, ErrConflict
}

// AppendAuditEvent is the narrow structural port implemented for policy,
// identity, approval, credential, and outbox projection adapters.
func (service *Service) AppendAuditEvent(ctx context.Context, event tamperaudit.Event) error {
	_, err := service.Append(ctx, event)
	return err
}

func (service *Service) appendAtHead(ctx context.Context, event tamperaudit.Event, now time.Time) (AppendResult, error) {
	head, err := service.store.LoadHead(ctx, event.OrganizationID, event.TenantID)
	if err != nil {
		return AppendResult{}, normalizeStoreError(err)
	}
	if err := validateHead(head, event.OrganizationID, event.TenantID); err != nil {
		return AppendResult{}, err
	}
	if head.Sequence == 0 {
		head.ChainHash = tamperaudit.GenesisHash
	}
	record, err := tamperaudit.BuildRecord(event, head.Sequence+1, head.ChainHash, formatTime(now))
	if err != nil {
		return AppendResult{}, ErrInvalidInput
	}
	checkpoint, err := service.checkpointFor(ctx, head, record, now)
	if err != nil {
		return AppendResult{}, err
	}
	commit := Commit{IdempotencyKey: event.EventID, RequestDigest: record.EventDigest,
		ExpectedHead: head, Record: record, Checkpoint: checkpoint}
	result, err := service.store.CommitAudit(ctx, commit)
	if err != nil {
		return AppendResult{}, normalizeStoreError(err)
	}
	if result.Replayed {
		if result.Sequence == 0 || !validDigest(result.ChainHash) {
			return AppendResult{}, ErrIntegrity
		}
		return result, nil
	}
	if result.Sequence != record.Sequence ||
		subtle.ConstantTimeCompare([]byte(result.ChainHash), []byte(record.ChainHash)) != 1 {
		return AppendResult{}, ErrIntegrity
	}
	if checkpoint != nil && result.CheckpointID != checkpoint.CheckpointID || checkpoint == nil && result.CheckpointID != "" {
		return AppendResult{}, ErrIntegrity
	}
	return result, nil
}

func validateHead(head tamperaudit.Head, organizationID, tenantID string) error {
	if head.Sequence == 0 {
		if head.OrganizationID == "" && head.TenantID == "" && (head.ChainHash == "" || head.ChainHash == tamperaudit.GenesisHash) {
			return nil
		}
		return ErrIntegrity
	}
	if head.OrganizationID != organizationID || head.TenantID != tenantID || head.ChainHash == "" ||
		head.LastRecordAt == "" || !validDigest(head.ChainHash) || mustTime(head.LastRecordAt).IsZero() ||
		head.LastCheckpointSequence > head.Sequence {
		return ErrIntegrity
	}
	return nil
}

func normalizeStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIntegrity):
		return err
	case workflowbase.StorageCode(err) == workflowbase.StorageConflict:
		return ErrConflict
	case workflowbase.StorageCode(err) == workflowbase.StorageDenied:
		return ErrIntegrity
	default:
		return ErrUnavailable
	}
}

func formatTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func mustTime(value string) time.Time {
	parsed, _ := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return parsed
}

func validDigest(value string) bool {
	if len(value) != len(tamperaudit.GenesisHash) || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
