package evidencepackage

import (
	"context"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type InputStore interface {
	OpenInput(context.Context, string) (io.ReadCloser, error)
}

type ArtifactSink interface {
	StageArtifact(context.Context, uint16, evidencelifecycle.EvidenceReference, io.Reader) (
		evidencelifecycle.StagedImportArtifact, error)
}

type ProofVerification struct {
	CustodyReportDigest   string
	AuditCheckpointDigest string
}

type ProofVerifier interface {
	VerifyExportProof(context.Context, evidencelifecycle.ExportManifest) (ProofVerification, error)
}

type Clock interface{ Now() time.Time }

type VerificationProfile struct {
	TrustSnapshotDigest string
	RevocationDigest    string
}

type Worker struct {
	inputs    InputStore
	sink      ArtifactSink
	signature evidencelifecycle.SignatureVerifier
	proof     ProofVerifier
	clock     Clock
	profile   VerificationProfile
}

func NewWorker(inputs InputStore, sink ArtifactSink, signature evidencelifecycle.SignatureVerifier,
	proof ProofVerifier, clock Clock, profile VerificationProfile) (*Worker, error) {
	if inputs == nil || sink == nil || signature == nil || proof == nil || clock == nil ||
		!validDigestText(profile.TrustSnapshotDigest) || !validDigestText(profile.RevocationDigest) {
		return nil, packageError("import worker dependencies are invalid")
	}
	return &Worker{inputs, sink, signature, proof, clock, profile}, nil
}

var _ evidencelifecycle.PackageReader = (*Worker)(nil)
