package evidencepackage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestAdapterBuildsCommitsVerifiesAndRecoversQuarantine(t *testing.T) {
	payload := []byte(`{"event":"verified"}`)
	manifest, signature := packageFixture(t, payload)
	quarantine := &memoryQuarantine{objects: make(map[string][]byte), packages: make(map[string]evidencelifecycle.QuarantinedPackage)}
	adapter, err := New(quarantine, packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: payload})
	if err != nil {
		t.Fatal(err)
	}
	value, err := adapter.BuildPackage(t.Context(), evidencelifecycle.PackageBuildRequest{Manifest: manifest,
		Signature: signature, Evidence: evidencelifecycle.VerifiedEvidenceSet{Case: manifest.Case,
			Artifacts: manifest.Artifacts, ArtifactSetDigest: manifest.ArtifactSetDigest}, Deadline: manifest.ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.VerifyPackage(t.Context(), value, manifest.Limits); err != nil {
		t.Fatal(err)
	}
	recovered, found, err := adapter.RecoverPackage(t.Context(), manifest.Case, value.PackageDigest)
	if err != nil || !found || recovered != value {
		t.Fatalf("recovered=%+v found=%v err=%v", recovered, found, err)
	}
	recoveredManifest, recoveredSignature, err := adapter.RecoverPackageProof(t.Context(), recovered, manifest.Limits)
	if err != nil || recoveredManifest.ManifestDigest != manifest.ManifestDigest || recoveredSignature != signature {
		t.Fatalf("manifest=%+v signature=%+v err=%v", recoveredManifest, recoveredSignature, err)
	}
	quarantine.objects[value.Reference][fixedHeaderLength] ^= 1
	if err = adapter.VerifyPackage(t.Context(), value, manifest.Limits); err == nil {
		t.Fatal("tampered quarantine object verified")
	}
}

func TestAdapterAbandonsFailedBuild(t *testing.T) {
	payload := []byte("expected")
	manifest, signature := packageFixture(t, payload)
	quarantine := &memoryQuarantine{objects: make(map[string][]byte), packages: make(map[string]evidencelifecycle.QuarantinedPackage)}
	adapter, _ := New(quarantine, packageSources{manifest.Artifacts[0].Reference.Artifact.Digest: []byte("tampered")})
	if _, err := adapter.BuildPackage(t.Context(), evidencelifecycle.PackageBuildRequest{Manifest: manifest,
		Signature: signature, Evidence: evidencelifecycle.VerifiedEvidenceSet{Case: manifest.Case,
			Artifacts: manifest.Artifacts, ArtifactSetDigest: manifest.ArtifactSetDigest}, Deadline: manifest.ValidUntil}); err == nil {
		t.Fatal("tampered build succeeded")
	}
	if !quarantine.abandoned || len(quarantine.objects) != 0 {
		t.Fatal("failed quarantine object was not abandoned")
	}
}

type memoryQuarantine struct {
	objects   map[string][]byte
	packages  map[string]evidencelifecycle.QuarantinedPackage
	abandoned bool
}

func (store *memoryQuarantine) Create(context.Context, domain.CaseRef, string) (QuarantineObject, error) {
	return &memoryObject{store: store}, nil
}
func (store *memoryQuarantine) Open(_ context.Context, reference string) (io.ReadCloser, error) {
	value, found := store.objects[reference]
	if !found {
		return nil, errors.New("missing")
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}
func (store *memoryQuarantine) Recover(_ context.Context, _ domain.CaseRef,
	digest string) (evidencelifecycle.QuarantinedPackage, bool, error) {
	value, found := store.packages[digest]
	return value, found, nil
}

type memoryObject struct {
	bytes.Buffer
	store *memoryQuarantine
}

func (object *memoryObject) Commit(_ context.Context, report EncodingReport, manifestDigest,
	signatureDigest string) (string, error) {
	reference := "quarantine.package.1"
	object.store.objects[reference] = append([]byte(nil), object.Bytes()...)
	object.store.packages[report.PackageDigest] = evidencelifecycle.QuarantinedPackage{Reference: reference,
		Header: report.Header, HeaderDigest: report.Header.HeaderDigest, PackageDigest: report.PackageDigest,
		PackageLength: report.PackageLength, ManifestDigest: manifestDigest, SignatureDigest: signatureDigest}
	return reference, nil
}
func (object *memoryObject) Abandon(context.Context) error {
	object.store.abandoned = true
	return nil
}
