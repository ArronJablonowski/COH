package evidencepackage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestWorkerVerifiesCompletePackageBeforeReturningStagedArtifacts(t *testing.T) {
	payload := []byte(`{"event":"verified"}`)
	manifest, signature := packageFixture(t, payload)
	var encoded bytes.Buffer
	report, err := Encode(t.Context(), &encoded, manifest, signature,
		packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: payload})
	if err != nil {
		t.Fatal(err)
	}
	sink := &workerSink{}
	worker := validWorker(t, encoded.Bytes(), sink, manifest.CreatedAt.Add(time.Minute))
	result, err := worker.VerifyImport(t.Context(), evidencelifecycle.ImportRequest{Reference: "staged.input.1",
		SourceDigest: workerDigest([]byte("source")), PackageDigest: report.PackageDigest,
		Limits: manifest.Limits, Deadline: manifest.ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verification.Outcome != evidencelifecycle.VerificationValid ||
		result.Verification.PackageDigest != report.PackageDigest || len(result.Staged) != 1 || sink.calls != 1 ||
		result.Staged[0].ArtifactDigest != manifest.Artifacts[0].Reference.Artifact.Digest {
		t.Fatalf("result=%+v calls=%d", result, sink.calls)
	}
}

func TestWorkerRejectsFramingTamperTrailingAndPayloadDrift(t *testing.T) {
	payload := []byte("expected-payload")
	manifest, signature := packageFixture(t, payload)
	var encoded bytes.Buffer
	report, err := Encode(t.Context(), &encoded, manifest, signature,
		packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: payload})
	if err != nil {
		t.Fatal(err)
	}
	base := encoded.Bytes()
	for name, mutate := range map[string]func([]byte) []byte{
		"magic":         func(value []byte) []byte { value[0] ^= 1; return value },
		"compression":   func(value []byte) []byte { value[10] = 1; return value },
		"header digest": func(value []byte) []byte { value[31] ^= 1; return value },
		"payload":       func(value []byte) []byte { value[len(value)-1] ^= 1; return value },
		"trailing":      func(value []byte) []byte { return append(value, 0) },
		"truncated":     func(value []byte) []byte { return value[:len(value)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			input := mutate(append([]byte(nil), base...))
			worker := validWorker(t, input, &workerSink{}, manifest.CreatedAt.Add(time.Minute))
			if _, err := worker.VerifyImport(t.Context(), evidencelifecycle.ImportRequest{Reference: "staged.input.1",
				SourceDigest: workerDigest([]byte("source")), PackageDigest: report.PackageDigest,
				Limits: manifest.Limits, Deadline: manifest.ValidUntil}); err == nil {
				t.Fatal("tampered package verified")
			}
		})
	}
}

func TestWorkerRejectsTrustProofAndResourceFailuresBeforeSuccess(t *testing.T) {
	payload := []byte("expected-payload")
	manifest, signature := packageFixture(t, payload)
	var encoded bytes.Buffer
	report, _ := Encode(t.Context(), &encoded, manifest, signature,
		packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: payload})
	for name, mutate := range map[string]func(*workerSignature, *workerProof){
		"signature":  func(signature *workerSignature, _ *workerProof) { signature.err = errors.New("denied") },
		"custody":    func(_ *workerSignature, proof *workerProof) { proof.custody = workerDigest([]byte("other")) },
		"checkpoint": func(_ *workerSignature, proof *workerProof) { proof.checkpoint = workerDigest([]byte("other")) },
	} {
		t.Run(name, func(t *testing.T) {
			signatureVerifier := &workerSignature{}
			proof := &workerProof{custody: manifest.CustodyReportDigest, checkpoint: manifest.AuditCheckpointDigest}
			mutate(signatureVerifier, proof)
			worker, _ := NewWorker(workerInputs{value: encoded.Bytes()}, &workerSink{}, signatureVerifier, proof,
				workerClock{manifest.CreatedAt.Add(time.Minute)}, VerificationProfile{
					TrustSnapshotDigest: workerDigest([]byte("trust")), RevocationDigest: workerDigest([]byte("revocation"))})
			if _, err := worker.VerifyImport(t.Context(), evidencelifecycle.ImportRequest{Reference: "staged.input.1",
				SourceDigest: workerDigest([]byte("source")), PackageDigest: report.PackageDigest,
				Limits: manifest.Limits, Deadline: manifest.ValidUntil}); err == nil {
				t.Fatal("invalid trust proof verified")
			}
		})
	}
}

func validWorker(t *testing.T, input []byte, sink *workerSink, now time.Time) *Worker {
	t.Helper()
	manifest, _ := packageFixture(t, []byte(`{"event":"verified"}`))
	worker, err := NewWorker(workerInputs{value: input}, sink, &workerSignature{},
		&workerProof{custody: manifest.CustodyReportDigest, checkpoint: manifest.AuditCheckpointDigest},
		workerClock{now}, VerificationProfile{TrustSnapshotDigest: workerDigest([]byte("trust")),
			RevocationDigest: workerDigest([]byte("revocation"))})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

type workerInputs struct{ value []byte }

func (store workerInputs) OpenInput(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(store.value)), nil
}

type workerSink struct{ calls int }

func (sink *workerSink) StageArtifact(_ context.Context, ordinal uint16,
	reference evidencelifecycle.EvidenceReference, reader io.Reader) (evidencelifecycle.StagedImportArtifact, error) {
	sink.calls++
	value, err := io.ReadAll(reader)
	if err != nil {
		return evidencelifecycle.StagedImportArtifact{}, err
	}
	return evidencelifecycle.StagedImportArtifact{Ordinal: ordinal, ArtifactDigest: reference.Artifact.Digest,
		Reference: "quarantine.artifact.1", VerificationDigest: workerDigest(value)}, nil
}

type workerSignature struct{ err error }

func (stub *workerSignature) VerifyDetachedSignature(context.Context,
	evidencelifecycle.VerifySignatureRequest) error {
	return stub.err
}

type workerProof struct {
	custody    string
	checkpoint string
}

func (stub *workerProof) VerifyExportProof(context.Context,
	evidencelifecycle.ExportManifest) (ProofVerification, error) {
	return ProofVerification{CustodyReportDigest: stub.custody, AuditCheckpointDigest: stub.checkpoint}, nil
}

type workerClock struct{ now time.Time }

func (clock workerClock) Now() time.Time { return clock.now }

func workerDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
