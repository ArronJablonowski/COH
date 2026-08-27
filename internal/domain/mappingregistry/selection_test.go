package mappingregistry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResolveVerifiedMappingSelectsExactCurrentManifest(t *testing.T) {
	fixture := newSelectionFixture(t)
	result, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	if result.ManifestDigest != fixture.signed.ManifestDigest || result.RegistryRevision != fixture.snapshot.Revision {
		t.Fatalf("result=%+v", result)
	}
	if fixture.schemas.calls != 1 || fixture.signatures.calls != 1 || fixture.store.snapshotCalls != 1 || fixture.store.mappingCalls != 1 {
		t.Fatalf("calls schema=%d signature=%d snapshot=%d mapping=%d", fixture.schemas.calls, fixture.signatures.calls, fixture.store.snapshotCalls, fixture.store.mappingCalls)
	}
	request := fixture.signatures.request
	if request.ManifestDigest != fixture.signed.ManifestDigest || request.PublisherID != fixture.signed.PublisherID ||
		request.KeyID != fixture.signed.PublisherKeyID || request.KeyRevision != fixture.signed.PublisherKeyRevision ||
		request.Algorithm != "ed25519" || request.Domain != signatureDomain || request.Signature != fixture.signed.Signature ||
		request.Purpose != mappingSignaturePurpose || request.NotBefore != fixture.signed.Manifest.NotBefore ||
		request.NotAfter != fixture.signed.Manifest.NotAfter || request.Revocation != fixture.signed.Manifest.Revocation {
		t.Fatalf("signature request=%+v", request)
	}
}

func TestResolveVerifiedMappingDeniesSelectionFailuresBeforeManifestLoad(t *testing.T) {
	tests := map[string]func(*selectionFixture){
		"not found":           func(value *selectionFixture) { value.store.snapshots = nil },
		"ambiguous":           func(value *selectionFixture) { value.store.snapshots = append(value.store.snapshots, value.snapshot) },
		"source substitution": func(value *selectionFixture) { value.store.snapshots[0].Source.Product = "other.product" },
		"identity substitution": func(value *selectionFixture) {
			digest := testDigest
			value.store.snapshots[0].Source.SourceIdentityDigest = &digest
		},
		"digest substitution": func(value *selectionFixture) { value.command.MappingDigest = testDigest },
		"downgrade digest": func(value *selectionFixture) {
			value.store.snapshots[0].PredecessorManifestDigest = testDigest
			value.command.MappingDigest = testDigest
		},
		"stale revision":   func(value *selectionFixture) { value.command.ExpectedRegistryRevision = value.snapshot.Revision - 1 },
		"future revision":  func(value *selectionFixture) { value.command.ExpectedRegistryRevision = value.snapshot.Revision + 1 },
		"invalid snapshot": func(value *selectionFixture) { value.store.snapshots[0].Revision = 0 },
	}
	wants := map[string]Reason{
		"not found": MappingNotFound, "ambiguous": MappingAmbiguous, "source substitution": SourceMismatch, "identity substitution": SourceMismatch,
		"digest substitution": ManifestDigestMismatch, "downgrade digest": MappingDowngrade,
		"stale revision": MappingDowngrade, "future revision": MappingNotFound, "invalid snapshot": DependencyUnavailableReason,
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newSelectionFixture(t)
			mutate(fixture)
			_, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command)
			if ErrorReason(err) != wants[name] || fixture.store.mappingCalls != 0 || fixture.signatures.calls != 0 {
				t.Fatalf("err=%v reason=%q mapping_calls=%d signature_calls=%d", err, ErrorReason(err), fixture.store.mappingCalls, fixture.signatures.calls)
			}
		})
	}
}

func TestResolveVerifiedMappingDeniesManifestAndAuthorityDrift(t *testing.T) {
	tests := map[string]struct {
		mutate func(*selectionFixture)
		reason Reason
	}{
		"missing manifest": {func(value *selectionFixture) { value.store.found = false }, MappingNotFound},
		"manifest digest":  {func(value *selectionFixture) { value.store.signed.ManifestDigest = testDigest }, ManifestDigestMismatch},
		"target":           {func(value *selectionFixture) { value.store.signed.Manifest.Compatibility.ECSVersion = "changed" }, TargetIncompatible},
		"source": {func(value *selectionFixture) {
			value.store.signed.Manifest.Source.SourceSchemaVersion = "changed"
			refreshSigned(t, value)
		}, SourceMismatch},
		"not yet valid":     {func(value *selectionFixture) { value.clock.now = time.Date(2026, 8, 26, 23, 59, 59, 0, time.UTC) }, ManifestNotYetValid},
		"expired":           {func(value *selectionFixture) { value.clock.now = time.Date(2027, 8, 27, 0, 0, 0, 0, time.UTC) }, ManifestExpired},
		"clock unavailable": {func(value *selectionFixture) { value.clock.now = time.Time{} }, DependencyUnavailableReason},
		"invalid signature": {func(value *selectionFixture) { value.signatures.decision.Verified = false }, SignatureInvalid},
		"untrusted key":     {func(value *selectionFixture) { value.signatures.decision.TrustRevision++ }, PublisherUntrusted},
		"revoked":           {func(value *selectionFixture) { value.signatures.decision.Revoked = true }, ManifestRevoked},
		"stale revocation":  {func(value *selectionFixture) { value.signatures.decision.Revocation.MinimumRevision++ }, RevocationStale},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newSelectionFixture(t)
			test.mutate(fixture)
			_, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command)
			if ErrorReason(err) != test.reason {
				t.Fatalf("err=%v reason=%q want=%q", err, ErrorReason(err), test.reason)
			}
		})
	}
}

func TestResolveVerifiedMappingDependencyCancellationAndRecovery(t *testing.T) {
	fixture := newSelectionFixture(t)
	fixture.store.err = errors.New("store unavailable")
	if _, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command); Code(err) != UnavailableError || ErrorReason(err) != DependencyUnavailableReason {
		t.Fatalf("dependency err=%v", err)
	}

	fixture = newSelectionFixture(t)
	fixture.signatures.err = errors.New("verifier unavailable")
	if _, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command); Code(err) != UnavailableError || ErrorReason(err) != DependencyUnavailableReason {
		t.Fatalf("signature dependency err=%v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	fixture = newSelectionFixture(t)
	if _, err := resolveVerifiedMapping(canceled, fixture.dependencies(), fixture.command); Code(err) != CanceledError || !errors.Is(err, context.Canceled) || fixture.schemas.calls != 0 {
		t.Fatalf("cancellation err=%v schema_calls=%d", err, fixture.schemas.calls)
	}

	fixture = newSelectionFixture(t)
	if _, err := resolveVerifiedMapping(context.Background(), fixture.dependencies(), fixture.command); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

type selectionFixture struct {
	signed     SignedMapping
	snapshot   RegistrySnapshot
	command    Command
	store      *selectionStore
	schemas    *selectionSchemas
	signatures *selectionSignatures
	clock      fixedMappingClock
}

func newSelectionFixture(t *testing.T) *selectionFixture {
	t.Helper()
	signed := validSignedMapping(t)
	snapshot := RegistrySnapshot{Source: signed.Manifest.Source, Revision: 3, CurrentManifestDigest: signed.ManifestDigest, Revocation: signed.Manifest.Revocation}
	fixture := &selectionFixture{
		signed: signed, snapshot: snapshot,
		command: Command{Operation: Apply, Source: signed.Manifest.Source, MappingDigest: signed.ManifestDigest, ExpectedRegistryRevision: snapshot.Revision},
		store:   &selectionStore{snapshots: []RegistrySnapshot{snapshot}, signed: signed, found: true},
		schemas: &selectionSchemas{},
		clock:   fixedMappingClock{now: time.Date(2026, 8, 27, 1, 0, 0, 0, time.UTC)},
	}
	fixture.signatures = &selectionSignatures{decision: SignatureDecision{Verified: true, TrustRevision: signed.PublisherKeyRevision, Revocation: signed.Manifest.Revocation}}
	return fixture
}

func refreshSigned(t *testing.T, fixture *selectionFixture) {
	t.Helper()
	_, digest, err := CanonicalManifest(context.Background(), fixture.store.signed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.signed.ManifestDigest = digest
	fixture.store.snapshots[0].CurrentManifestDigest = digest
	fixture.command.MappingDigest = digest
}

func (value *selectionFixture) dependencies() Dependencies {
	return Dependencies{Signatures: value.signatures, SourceSchemas: value.schemas, Store: value.store, Clock: value.clock}
}

type selectionStore struct {
	snapshots                   []RegistrySnapshot
	signed                      SignedMapping
	found, began                bool
	err                         error
	snapshotCalls, mappingCalls int
}

func (store *selectionStore) LoadSnapshots(context.Context, Case, SourceMatcher) ([]RegistrySnapshot, error) {
	store.snapshotCalls++
	if store.err != nil {
		return nil, store.err
	}
	return append([]RegistrySnapshot(nil), store.snapshots...), nil
}
func (store *selectionStore) LoadSignedMapping(context.Context, string) (SignedMapping, bool, error) {
	store.mappingCalls++
	return store.signed, store.found, store.err
}
func (*selectionStore) LoadReceipt(context.Context, string) (Receipt, bool, error) {
	return Receipt{}, false, nil
}
func (*selectionStore) LoadCommandDigest(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (store *selectionStore) Begin(context.Context, Command, string) (bool, error) {
	return store.began, store.err
}
func (*selectionStore) Commit(context.Context, Commit) error { return nil }

type selectionSchemas struct {
	calls int
	err   error
}

func (resolver *selectionSchemas) VerifySourceSchema(context.Context, Case, SourceMatcher) error {
	resolver.calls++
	return resolver.err
}

type selectionSignatures struct {
	calls    int
	request  SignatureRequest
	decision SignatureDecision
	err      error
}

func (verifier *selectionSignatures) VerifySignature(_ context.Context, request SignatureRequest) (SignatureDecision, error) {
	verifier.calls++
	verifier.request = request
	return verifier.decision, verifier.err
}

type fixedMappingClock struct{ now time.Time }

func (clock fixedMappingClock) Now() time.Time { return clock.now }
