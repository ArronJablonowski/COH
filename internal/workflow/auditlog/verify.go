package auditlog

import (
	"context"
	"crypto/subtle"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

// Verify reads a complete tenant interval and proves sequence, scope, event
// digests, chain links, checkpoint coverage, signatures, and mandatory
// frequency against the durable head.
func (service *Service) Verify(ctx context.Context, organizationID, tenantID string) (VerificationReport, error) {
	if service == nil || ctx == nil || organizationID == "" || tenantID == "" {
		return VerificationReport{}, ErrInvalidInput
	}
	records, err := service.readAllRecords(ctx, organizationID, tenantID)
	if err != nil {
		return VerificationReport{}, err
	}
	checkpoints, err := service.store.ReadAuditCheckpoints(ctx, organizationID, tenantID)
	if err != nil {
		return VerificationReport{}, normalizeStoreError(err)
	}
	if err := service.verifyRecords(records, organizationID, tenantID); err != nil {
		return VerificationReport{}, err
	}
	if err := service.verifyCheckpoints(ctx, records, checkpoints, organizationID, tenantID); err != nil {
		return VerificationReport{}, err
	}
	return service.verifyDurableHead(ctx, records, checkpoints, organizationID, tenantID)
}

func (service *Service) readAllRecords(ctx context.Context, organizationID, tenantID string) ([]tamperaudit.Record, error) {
	var records []tamperaudit.Record
	var after uint64
	for {
		batch, err := service.store.ReadAuditRecords(ctx, organizationID, tenantID, after, readBatchSize)
		if err != nil {
			return nil, normalizeStoreError(err)
		}
		if len(batch) == 0 {
			return records, nil
		}
		if len(batch) > int(readBatchSize) {
			return nil, ErrIntegrity
		}
		records = append(records, batch...)
		after = batch[len(batch)-1].Sequence
		if len(batch) < int(readBatchSize) {
			return records, nil
		}
	}
}

func (service *Service) verifyRecords(records []tamperaudit.Record, organizationID, tenantID string) error {
	previousHash := tamperaudit.GenesisHash
	for index, record := range records {
		if record.OrganizationID != organizationID || record.TenantID != tenantID ||
			tamperaudit.VerifyRecord(record, uint64(index)+1, previousHash) != nil {
			return ErrIntegrity
		}
		previousHash = record.ChainHash
	}
	return nil
}

func (service *Service) verifyCheckpoints(ctx context.Context, records []tamperaudit.Record, checkpoints []tamperaudit.Checkpoint,
	organizationID, tenantID string) error {
	sort.Slice(checkpoints, func(left, right int) bool { return checkpoints[left].Sequence < checkpoints[right].Sequence })
	previousSequence := uint64(0)
	bySequence := make(map[uint64]tamperaudit.Checkpoint, len(checkpoints))
	for _, checkpoint := range checkpoints {
		if checkpoint.OrganizationID != organizationID || checkpoint.TenantID != tenantID || checkpoint.Sequence == 0 ||
			checkpoint.Sequence > uint64(len(records)) || checkpoint.CoveredFromSequence != previousSequence+1 ||
			checkpoint.RecordCount != checkpoint.Sequence-previousSequence {
			return ErrIntegrity
		}
		if _, duplicate := bySequence[checkpoint.Sequence]; duplicate ||
			subtle.ConstantTimeCompare([]byte(checkpoint.ChainHash), []byte(records[checkpoint.Sequence-1].ChainHash)) != 1 ||
			mustTime(checkpoint.CreatedAt).Before(mustTime(records[checkpoint.Sequence-1].AppendedAt)) {
			return ErrIntegrity
		}
		authority, err := service.resolver.ResolveAuditKey(ctx, checkpoint.SigningKeyID, checkpoint.SigningKeyRevision)
		if err != nil || !validAuthority(authority, checkpoint, service.clock.Now().UTC()) ||
			tamperaudit.VerifyCheckpoint(checkpoint, authority.PublicKey) != nil {
			return ErrIntegrity
		}
		bySequence[checkpoint.Sequence] = checkpoint
		previousSequence = checkpoint.Sequence
	}
	if uint64(len(records))-previousSequence >= tamperaudit.CheckpointRecordLimit {
		return ErrIntegrity
	}
	for index := 1; index < len(records); index++ {
		if crossedUTCDate(records[index-1].AppendedAt, mustTime(records[index].AppendedAt)) {
			if _, exists := bySequence[uint64(index)]; !exists {
				return ErrIntegrity
			}
		}
	}
	return nil
}

func (service *Service) verifyDurableHead(ctx context.Context, records []tamperaudit.Record, checkpoints []tamperaudit.Checkpoint,
	organizationID, tenantID string) (VerificationReport, error) {
	head, err := service.store.LoadHead(ctx, organizationID, tenantID)
	if err != nil {
		return VerificationReport{}, normalizeStoreError(err)
	}
	report := VerificationReport{OrganizationID: organizationID, TenantID: tenantID,
		RecordCount: uint64(len(records)), CheckpointCount: uint64(len(checkpoints)), HeadHash: tamperaudit.GenesisHash}
	if len(records) == 0 {
		if validateHead(head, organizationID, tenantID) != nil {
			return VerificationReport{}, ErrIntegrity
		}
		return report, nil
	}
	last := records[len(records)-1]
	report.HeadSequence, report.HeadHash = last.Sequence, last.ChainHash
	if len(checkpoints) > 0 {
		report.LastCheckpoint = checkpoints[len(checkpoints)-1].Sequence
	}
	report.UncheckpointedCount = report.HeadSequence - report.LastCheckpoint
	if validateHead(head, organizationID, tenantID) != nil || head.Sequence != report.HeadSequence ||
		subtle.ConstantTimeCompare([]byte(head.ChainHash), []byte(report.HeadHash)) != 1 ||
		head.LastCheckpointSequence != report.LastCheckpoint {
		return VerificationReport{}, ErrIntegrity
	}
	return report, nil
}
