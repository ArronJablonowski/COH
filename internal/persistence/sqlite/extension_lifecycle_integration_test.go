package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type lifecycleFixture struct {
	envelope []byte
	intent   []byte
	snapshot extensionlifecycle.AuthoritySnapshot
}

type lifecycleClock struct{ now time.Time }

func (clock lifecycleClock) Now() time.Time { return clock.now }

type persistentEffects struct {
	mu      sync.Mutex
	results map[string]extensionlifecycle.EffectResult
}

func (effects *persistentEffects) Resolve(_ context.Context, request extensionlifecycle.EffectRequest) (extensionlifecycle.EffectResult, bool, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	value, ok := effects.results[request.EffectKey]
	return value, ok, nil
}
func (effects *persistentEffects) Stage(_ context.Context, request extensionlifecycle.EffectRequest) (extensionlifecycle.EffectResult, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if value, ok := effects.results[request.EffectKey]; ok {
		return value, nil
	}
	value := extensionlifecycle.EffectResult{ReceiptID: lifecycleUUID(30 + request.Ordinal), HandleID: lifecycleUUID(40 + request.Ordinal),
		Generation: request.Ordinal + 1, RegistryRevision: request.RegistryRevision, EffectAuditDigest: lifecycleDigest('e'),
		RegisteredAt: "2026-08-28T08:00:00Z"}
	effects.results[request.EffectKey] = value
	return value, nil
}
func (effects *persistentEffects) Revoke(_ context.Context, request extensionlifecycle.EffectRequest, handle extensionlifecycle.RevocationHandle) (extensionlifecycle.RevocationResult, error) {
	effects.mu.Lock()
	defer effects.mu.Unlock()
	if handle.ExtensionID != request.ExtensionID || handle.RegistrationOrdinal != request.Ordinal {
		return extensionlifecycle.RevocationResult{}, errors.New("owner mismatch")
	}
	return extensionlifecycle.RevocationResult{RevokedAt: "2026-08-28T08:00:01Z", EffectAuditDigest: lifecycleDigest('d')}, nil
}

type lifecycleAudit struct{}

func (*lifecycleAudit) CommitActivation(context.Context, string, string, []string) (string, error) {
	return lifecycleDigest('a'), nil
}
func (*lifecycleAudit) CommitDeactivation(context.Context, string, string, string, []string) (string, error) {
	return lifecycleDigest('b'), nil
}

type lifecycleDrain struct{}

func (*lifecycleDrain) CloseAdmissionsAndDrain(_ context.Context, request extensionlifecycle.DrainRequest) (extensionlifecycle.DrainAttestation, error) {
	return extensionlifecycle.DrainAttestation{TransitionID: request.TransitionID, AdmissionsClosed: true, Durable: true, TerminalOutcomesDigest: lifecycleDigest('c')}, nil
}

type lostLifecycleResponse struct {
	extensionlifecycle.ActivationStore
	operation string
	fired     bool
}

func (store *lostLifecycleResponse) lost(operation string) error {
	if !store.fired && store.operation == operation {
		store.fired = true
		return errors.New("durable response lost")
	}
	return nil
}
func (store *lostLifecycleResponse) CreateTransition(ctx context.Context, value extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.CreateTransition(ctx, value)
	if err == nil {
		err = store.lost("create_" + string(value.Direction))
	}
	return result, err
}
func (store *lostLifecycleResponse) AdvanceTransition(ctx context.Context, current, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.AdvanceTransition(ctx, current, next)
	if err == nil {
		err = store.lost("advance_" + string(next.Phase))
	}
	return result, err
}
func (store *lostLifecycleResponse) CommitReceipt(ctx context.Context, current extensionlifecycle.Transition, receipt extensionlifecycle.RegistrationReceipt, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.CommitReceipt(ctx, current, receipt, next)
	if err == nil {
		err = store.lost("receipt")
	}
	return result, err
}
func (store *lostLifecycleResponse) CommitRevocation(ctx context.Context, current extensionlifecycle.Transition, before, after extensionlifecycle.RegistrationReceipt, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.CommitRevocation(ctx, current, before, after, next)
	if err == nil {
		err = store.lost("revocation")
	}
	return result, err
}
func (store *lostLifecycleResponse) PublishActive(ctx context.Context, current extensionlifecycle.Transition, active extensionlifecycle.ActiveExtension, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.PublishActive(ctx, current, active, next)
	if err == nil {
		err = store.lost("publish")
	}
	return result, err
}
func (store *lostLifecycleResponse) RemoveActive(ctx context.Context, current extensionlifecycle.Transition, active extensionlifecycle.ActiveExtension, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	result, err := store.ActivationStore.RemoveActive(ctx, current, active, next)
	if err == nil {
		err = store.lost("remove")
	}
	return result, err
}

func TestExtensionActivationRecoversCommittedLostResponsesAfterSQLiteRestart(t *testing.T) {
	for _, operation := range []string{"create_activate", "advance_applying", "receipt", "publish"} {
		t.Run(operation, func(t *testing.T) {
			path, backup := lifecycleStorePaths(t)
			store := openProfileActivationStore(t, path, backup)
			fixture := newLifecycleFixture(t)
			admission := verifyLifecycleFixture(t, fixture)
			effects := &persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}
			fault := &lostLifecycleResponse{ActivationStore: store.ExtensionLifecycle(), operation: operation}
			controller, _ := extensionlifecycle.NewActivationController(fault, effects, &lifecycleAudit{}, lifecycleClock{profileActivationTime})
			if _, err := controller.Activate(context.Background(), admission); extensionlifecycle.Code(err) != extensionlifecycle.Unavailable {
				t.Fatalf("first err=%v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := openProfileActivationStore(t, path, backup)
			t.Cleanup(func() { _ = restarted.Close() })
			fresh := verifyLifecycleFixture(t, fixture)
			controller, _ = extensionlifecycle.NewActivationController(restarted.ExtensionLifecycle(), effects, &lifecycleAudit{}, lifecycleClock{profileActivationTime})
			result, err := controller.Activate(context.Background(), fresh)
			if err != nil || !result.Replayed || result.Transition.Phase != extensionlifecycle.ActivePhase {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			manifest, found, loadErr := restarted.ExtensionLifecycle().LoadManifest(context.Background(), fresh.Envelope().ManifestDigest())
			if loadErr != nil || !found || !bytes.Equal(manifest, fresh.Envelope().CanonicalBytes()) {
				t.Fatalf("manifest found=%v err=%v", found, loadErr)
			}
		})
	}
}

func TestExtensionDeactivationRecoversCommittedLostResponsesAfterSQLiteRestart(t *testing.T) {
	for _, operation := range []string{"create_deactivate", "advance_draining", "advance_revoking", "revocation", "remove"} {
		t.Run(operation, func(t *testing.T) {
			path, backup := lifecycleStorePaths(t)
			store := openProfileActivationStore(t, path, backup)
			fixture := newLifecycleFixture(t)
			admission := verifyLifecycleFixture(t, fixture)
			effects, audit := &persistentEffects{results: map[string]extensionlifecycle.EffectResult{}}, &lifecycleAudit{}
			activate, _ := extensionlifecycle.NewActivationController(store.ExtensionLifecycle(), effects, audit, lifecycleClock{profileActivationTime})
			active, err := activate.Activate(context.Background(), admission)
			if err != nil {
				t.Fatal(err)
			}
			deactivationFixture := lifecycleDeactivationFixture(t, fixture, active.Active)
			deactivation := verifyLifecycleFixture(t, deactivationFixture)
			fault := &lostLifecycleResponse{ActivationStore: store.ExtensionLifecycle(), operation: operation}
			controller, _ := extensionlifecycle.NewDeactivationController(fault, effects, audit, &lifecycleDrain{}, lifecycleClock{profileActivationTime})
			if _, err := controller.Deactivate(context.Background(), deactivation); extensionlifecycle.Code(err) != extensionlifecycle.Unavailable {
				t.Fatalf("first err=%v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := openProfileActivationStore(t, path, backup)
			t.Cleanup(func() { _ = restarted.Close() })
			fresh := verifyLifecycleFixture(t, deactivationFixture)
			controller, _ = extensionlifecycle.NewDeactivationController(restarted.ExtensionLifecycle(), effects, audit, &lifecycleDrain{}, lifecycleClock{profileActivationTime})
			result, err := controller.Deactivate(context.Background(), fresh)
			if err != nil || !result.Replayed || result.Transition.Phase != extensionlifecycle.InactivePhase {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			intent := fresh.Intent().Value()
			if _, found, _ := restarted.ExtensionLifecycle().LoadActive(context.Background(), intent.ExtensionID, intent.OrganizationID, intent.TenantID); found {
				t.Fatal("active remains")
			}
			predecessor, found, predecessorErr := restarted.ExtensionLifecycle().LoadInactivePredecessor(context.Background(),
				intent.ExtensionID, intent.OrganizationID, intent.TenantID, intent.ManifestDigest, intent.ExpectedLifecycleRevision)
			if predecessorErr != nil || !found || predecessor.Phase != extensionlifecycle.InactivePhase {
				t.Fatalf("predecessor=%+v found=%v err=%v", predecessor, found, predecessorErr)
			}
		})
	}
}

func lifecycleStorePaths(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "coh.sqlite3"), backup
}
func verifyLifecycleFixture(t *testing.T, fixture lifecycleFixture) extensionlifecycle.ValidatedAdmission {
	t.Helper()
	value, err := extensionlifecycle.VerifyAdmission(context.Background(), fixture.envelope, fixture.intent, fixture.snapshot, lifecycleClock{profileActivationTime})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newLifecycleFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	now := profileActivationTime
	manifest := extensionlifecycle.Manifest{SchemaVersion: extensionlifecycle.ManifestSchemaVersion, ContractVersion: extensionlifecycle.ContractVersion, ExtensionID: lifecycleUUID(1), ExtensionName: "timeline_provider", ExtensionVersion: "1.0.0", ExtensionKind: "skill_provider", OwnerActorID: lifecycleUUID(8), OwnerModule: "timeline_extension", ArtifactDigest: lifecycleDigest('1'), SBOMDigest: lifecycleDigest('2'), ProvenanceDigest: lifecycleDigest('3'), TestEvidenceDigest: lifecycleDigest('4'), ThreatModelDigest: lifecycleDigest('5'), DeclaredPermissions: []string{"read.timeline"}, DeclaredScopeTypes: []string{"case", "organization", "task", "tenant"}, Dependencies: []extensionlifecycle.CapabilityRef{{CapabilityID: "analysis.events", CapabilityVersion: "1.0.0"}}, Registrations: []extensionlifecycle.Registration{{RegistrationID: "timeline_reader", Role: "provider", Capability: extensionlifecycle.CapabilityRef{CapabilityID: "analysis.timeline", CapabilityVersion: "1.0.0"}, ProviderID: "extension.timeline", Permissions: []string{"read.timeline"}, ScopeTypes: []string{"case", "organization", "tenant"}, ResourceLimitsDigest: lifecycleDigest('6')}}, MaximumActiveWork: 16, MaximumDrainDurationMS: 60000, ReviewDigest: lifecycleDigest('7'), ValidFrom: "2026-08-28T00:00:00Z", ValidUntil: "2026-08-29T00:00:00Z"}
	_, manifestDigest, err := extensionlifecycle.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PrivateKey{}
	for _, role := range []string{"administrator", "owner", "publisher", "reviewer"} {
		keys[role] = lifecycleKey(role)
	}
	envelope := extensionlifecycle.Envelope{SchemaVersion: extensionlifecycle.EnvelopeSchemaVersion, ContractVersion: extensionlifecycle.ContractVersion, Manifest: manifest, ManifestDigest: manifestDigest,
		PublisherSignature: lifecycleSignature("publisher", lifecycleUUID(2), manifestDigest, "COH-PUBLISHED-EXTENSION-V1\x00", keys["publisher"]), ReviewSignatures: []extensionlifecycle.Signature{lifecycleSignature("reviewer", lifecycleUUID(3), manifestDigest, "COH-REVIEWED-EXTENSION-V1\x00", keys["reviewer"])}, OwnerSignature: lifecycleSignature("owner", manifest.OwnerActorID, manifestDigest, "COH-OWNED-EXTENSION-V1\x00", keys["owner"])}
	envelopeBytes := lifecycleCanonical(t, envelope)
	scope := extensionlifecycle.ExactScope{OrganizationID: lifecycleUUID(5), TenantID: lifecycleUUID(6), CaseID: lifecycleUUID(7)}
	scopeDigest, _ := extensionlifecycle.ScopeDigest(scope)
	permissions := []string{"read.timeline"}
	permissionsDigest, _ := extensionlifecycle.PermissionsDigest(permissions)
	intent := extensionlifecycle.ActivationIntent{SchemaVersion: extensionlifecycle.IntentSchemaVersion, ContractVersion: extensionlifecycle.ContractVersion, RequestID: lifecycleUUID(10), IdempotencyKey: lifecycleUUID(11), ActorID: lifecycleUUID(4), ActorKind: "administrator", OrganizationID: scope.OrganizationID, TenantID: scope.TenantID, ExtensionID: manifest.ExtensionID, ManifestDigest: manifestDigest, Operation: "activate", Mode: "maintenance", RequestedScopeDigest: scopeDigest, RequestedPermissionsDigest: permissionsDigest, ActiveProfileRevision: 3, ProfileBindingDigest: lifecycleDigest('8'), CompositionDigest: lifecycleDigest('9'), CapabilityGraphDigest: lifecycleDigest('a'), ExpectedRegistryRevision: 11, PolicyDecisionDigest: lifecycleDigest('b'), PromotionSnapshotDigest: lifecycleDigest('c'), QualificationSnapshotDigest: lifecycleDigest('d'), AuditAvailabilityDigest: lifecycleDigest('e'), EStopState: "armed", EStopRevision: 5, MaximumDrainDurationMS: 30000, IssuedAt: "2026-08-28T07:59:00Z", DeadlineAt: "2026-08-28T08:01:00Z"}
	intent, err = extensionlifecycle.SealIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.AdministratorSignature = lifecycleSignature("administrator", intent.ActorID, intent.IntentDigest, "COH-SIGNED-EXTENSION-LIFECYCLE-V1\x00", keys["administrator"])
	records := []extensionlifecycle.SigningAuthority{lifecycleAuthority("administrator", intent.ActorID, keys["administrator"], now), lifecycleAuthority("owner", manifest.OwnerActorID, keys["owner"], now), lifecycleAuthority("publisher", envelope.PublisherSignature.ActorID, keys["publisher"], now), lifecycleAuthority("reviewer", envelope.ReviewSignatures[0].ActorID, keys["reviewer"], now)}
	sort.Slice(records, func(i, j int) bool { return records[i].Role+records[i].ActorID < records[j].Role+records[j].ActorID })
	snapshot := extensionlifecycle.AuthoritySnapshot{CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), AuthorityRevision: 7, RegistryRevision: 11, ManifestDigest: manifestDigest, ReviewDigest: manifest.ReviewDigest, PromotionSnapshotDigest: intent.PromotionSnapshotDigest, QualificationSnapshotDigest: intent.QualificationSnapshotDigest, PolicyDecisionDigest: intent.PolicyDecisionDigest, AuditAvailabilityDigest: intent.AuditAvailabilityDigest, ProfileRevision: 3, ProfileBindingDigest: intent.ProfileBindingDigest, CompositionDigest: intent.CompositionDigest, CapabilityGraphDigest: intent.CapabilityGraphDigest, EStopState: "armed", EStopRevision: 5, Scope: scope, Permissions: permissions, PromotionActive: true, ReviewActive: true, QualificationActive: true, PolicyAllowed: true, AuditAvailable: true, DependenciesQualified: true, Records: records}
	return lifecycleFixture{envelope: envelopeBytes, intent: lifecycleCanonical(t, intent), snapshot: snapshot}
}

func lifecycleDeactivationFixture(t *testing.T, source lifecycleFixture, active extensionlifecycle.ActiveExtension) lifecycleFixture {
	t.Helper()
	validated, _ := extensionlifecycle.DecodeIntent(context.Background(), source.intent)
	intent := validated.Value()
	intent.RequestID, intent.IdempotencyKey, intent.Operation, intent.ExpectedLifecycleRevision = lifecycleUUID(20), lifecycleUUID(21), "deactivate", active.LifecycleRevision
	intent.Mode, intent.ExpectedPredecessorManifestDigest, intent.RollbackAuthorizationDigest = "maintenance", "", ""
	intent, _ = extensionlifecycle.SealIntent(intent)
	intent.AdministratorSignature = lifecycleSignature("administrator", intent.ActorID, intent.IntentDigest, "COH-SIGNED-EXTENSION-LIFECYCLE-V1\x00", lifecycleKey("administrator"))
	return lifecycleFixture{envelope: source.envelope, intent: lifecycleCanonical(t, intent), snapshot: source.snapshot}
}
func lifecycleAuthority(role, actor string, private ed25519.PrivateKey, now time.Time) extensionlifecycle.SigningAuthority {
	return extensionlifecycle.SigningAuthority{Role: role, ActorID: actor, KeyID: role + "_key", KeyRevision: 1, ApprovalRevision: 1, AuthorityRevision: 7, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), Active: true, PublicKey: private.Public().(ed25519.PublicKey)}
}
func lifecycleSignature(role, actor, digest, domain string, private ed25519.PrivateKey) extensionlifecycle.Signature {
	raw, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return extensionlifecycle.Signature{ActorID: actor, KeyID: role + "_key", KeyRevision: 1, ApprovalRevision: 1, Algorithm: "ed25519", Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(domain), raw...)))}
}
func lifecycleKey(role string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("CYB-184/sqlite/" + role))
	return ed25519.NewKeyFromSeed(seed[:])
}
func lifecycleDigest(value byte) string { return "sha256:" + string(bytes.Repeat([]byte{value}, 64)) }
func lifecycleUUID(value uint64) string {
	return fmt.Sprintf("0198d6c4-%04x-7000-8000-%012x", value&0xffff, value)
}
func lifecycleCanonical(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
