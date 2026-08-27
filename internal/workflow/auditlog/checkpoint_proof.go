package auditlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type checkpointProofWire struct {
	CheckpointID       string `json:"checkpoint_id"`
	CheckpointDigest   string `json:"checkpoint_digest"`
	Sequence           uint64 `json:"sequence"`
	SigningKeyRevision uint64 `json:"signing_key_revision"`
	AuditHeadSequence  uint64 `json:"audit_head_sequence"`
	AuditHeadHash      string `json:"audit_head_hash"`
}

// ResolveCheckpointProof verifies the complete durable audit log and returns
// a digest-bound proof for one exact signed checkpoint.
func (service *Service) ResolveCheckpointProof(ctx context.Context, organizationID, tenantID,
	checkpointID, checkpointDigest string, minimumSequence uint64) (CheckpointProof, error) {
	if service == nil || ctx == nil || organizationID == "" || tenantID == "" ||
		checkpointID == "" || checkpointDigest == "" || minimumSequence == 0 {
		return CheckpointProof{}, ErrInvalidInput
	}
	report, err := service.Verify(ctx, organizationID, tenantID)
	if err != nil {
		return CheckpointProof{}, err
	}
	checkpoints, err := service.store.ReadAuditCheckpoints(ctx, organizationID, tenantID)
	if err != nil {
		return CheckpointProof{}, normalizeStoreError(err)
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.CheckpointID != checkpointID {
			continue
		}
		digest, digestErr := CheckpointDigest(checkpoint)
		if digestErr != nil || digest != checkpointDigest || checkpoint.Sequence < minimumSequence ||
			checkpoint.Sequence > report.HeadSequence {
			return CheckpointProof{}, ErrIntegrity
		}
		wire := checkpointProofWire{CheckpointID: checkpoint.CheckpointID, CheckpointDigest: digest,
			Sequence: checkpoint.Sequence, SigningKeyRevision: checkpoint.SigningKeyRevision,
			AuditHeadSequence: report.HeadSequence, AuditHeadHash: report.HeadHash}
		canonical, canonicalErr := canonicalCheckpointProof(wire)
		if canonicalErr != nil {
			return CheckpointProof{}, ErrIntegrity
		}
		return CheckpointProof{CheckpointID: checkpoint.CheckpointID, CheckpointDigest: digest,
			Sequence: checkpoint.Sequence, SigningKeyRevision: checkpoint.SigningKeyRevision,
			ProofDigest: domainDigest("COH-AUDIT-CHECKPOINT-PROOF-V1\x00", canonical)}, nil
	}
	return CheckpointProof{}, ErrIntegrity
}

// CheckpointDigest returns the content digest of one canonical signed audit
// checkpoint. Callers must still verify its signature and durable ancestry.
func CheckpointDigest(checkpoint tamperaudit.Checkpoint) (string, error) {
	canonical, err := tamperaudit.CanonicalCheckpoint(checkpoint)
	if err != nil {
		return "", err
	}
	return domainDigest("", canonical), nil
}

func canonicalCheckpointProof(value checkpointProofWire) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return domaincontract.Canonicalize(encoded)
}

func domainDigest(domainName string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domainName))
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
