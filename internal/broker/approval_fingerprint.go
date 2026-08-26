package broker

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
)

type approvalFingerprintEngine struct{ engine *approvalfingerprint.Engine }

var _ approvalFingerprintVerifier = approvalFingerprintEngine{}

func (adapter approvalFingerprintEngine) verifyApproval(ctx context.Context, candidate approvalfingerprint.Fingerprint,
	manifest actionmanifest.VerifiedEnvelope, signer actionmanifest.SignerAuthority, decision policy.Decision) (approvalVerifiedProof, error) {
	if adapter.engine == nil {
		return approvalVerifiedProof{}, lifecycle.NewError(lifecycle.Unavailable, "fingerprint_authority")
	}
	verified, err := adapter.engine.Verify(ctx, candidate, manifest, signer, decision)
	if err != nil {
		return approvalVerifiedProof{}, err
	}
	return approvalVerifiedProof{Fingerprint: verified, ActionTier: manifest.Manifest().ActionTier}, nil
}
