package mappingregistry

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestServiceExecutesCompleteRegistryLifecycleAndRevocationBlocksApply(t *testing.T) {
	fixture := newServiceFixture(t)
	first := cloneSignedMapping(fixture.input.selected.Signed)
	fixture.store.mappings = make(map[string]SignedMapping)
	fixture.store.snapshots = nil

	registerFirst := lifecycleCommand(fixture.command, Register, "011", first.ManifestDigest, 0)
	registerFirst.SignedMapping = &first
	assertLifecycleReceipt(t, fixture.service, registerFirst, Registered, RegisteredReason, 0)
	if commits := fixture.store.committed(); len(commits) != 1 || commits[0].SignedMapping == nil || commits[0].Snapshot != nil {
		t.Fatalf("register commits=%+v", commits)
	}

	promoteFirst := lifecycleCommand(fixture.command, Promote, "012", first.ManifestDigest, 0)
	assertLifecycleReceipt(t, fixture.service, promoteFirst, Promoted, PromotedReason, 1)
	assertCurrentSnapshot(t, fixture.store, first.ManifestDigest, "", 1, false)

	second := cloneSignedMapping(first)
	second.Manifest.Version = "1.1.0"
	second.Manifest.Revision = 2
	second.Manifest.PredecessorDigest = &first.ManifestDigest
	_, secondDigest, err := CanonicalManifest(context.Background(), second.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	second.ManifestDigest = secondDigest
	registerSecond := lifecycleCommand(fixture.command, Register, "013", secondDigest, 0)
	registerSecond.SignedMapping = &second
	assertLifecycleReceipt(t, fixture.service, registerSecond, Registered, RegisteredReason, 0)

	promoteSecond := lifecycleCommand(fixture.command, Promote, "014", secondDigest, 1)
	assertLifecycleReceipt(t, fixture.service, promoteSecond, Promoted, PromotedReason, 2)
	assertCurrentSnapshot(t, fixture.store, secondDigest, first.ManifestDigest, 2, false)

	rollback := lifecycleCommand(fixture.command, Rollback, "015", first.ManifestDigest, 2)
	assertLifecycleReceipt(t, fixture.service, rollback, RolledBack, RolledBackReason, 3)
	assertCurrentSnapshot(t, fixture.store, first.ManifestDigest, "", 3, false)

	revoke := lifecycleCommand(fixture.command, Revoke, "016", first.ManifestDigest, 3)
	assertLifecycleReceipt(t, fixture.service, revoke, Revoked, RevokedReason, 4)
	assertCurrentSnapshot(t, fixture.store, first.ManifestDigest, "", 4, true)

	apply := lifecycleCommand(fixture.command, Apply, "017", first.ManifestDigest, 4)
	receipt, err := fixture.service.Execute(context.Background(), apply, &fixture.input.input)
	if Code(err) != DeniedError || ErrorReason(err) != ManifestRevoked || receipt.Status != Denied || receipt.ReasonCode != ManifestRevoked {
		t.Fatalf("apply receipt=%+v err=%v", receipt, err)
	}
	commits := fixture.store.committed()
	if len(commits) != 7 || commits[len(commits)-1].NormalizedEnvelope != nil {
		t.Fatalf("commits=%+v", commits)
	}
}

func TestServiceRegistryLifecycleRejectsStaleAndCollidingMutations(t *testing.T) {
	t.Run("stale promotion", func(t *testing.T) {
		fixture := newServiceFixture(t)
		command := lifecycleCommand(fixture.command, Promote, "021", fixture.command.MappingDigest, 2)
		receipt, err := fixture.service.Execute(context.Background(), command, nil)
		if Code(err) != DeniedError || ErrorReason(err) != MappingDowngrade || receipt.Status != Denied || receipt.ReasonCode != MappingDowngrade {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
		if len(fixture.store.committed()) != 1 || fixture.store.committed()[0].Snapshot != nil {
			t.Fatalf("commits=%+v", fixture.store.committed())
		}
	})

	t.Run("immutable registration collision", func(t *testing.T) {
		fixture := newServiceFixture(t)
		colliding := cloneSignedMapping(fixture.input.selected.Signed)
		colliding.Signature = base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 63)...))
		command := lifecycleCommand(fixture.command, Register, "022", colliding.ManifestDigest, 0)
		command.SignedMapping = &colliding
		receipt, err := fixture.service.Execute(context.Background(), command, nil)
		if Code(err) != ConflictError || ErrorReason(err) != ManifestDigestMismatch ||
			receipt.Status != Denied || receipt.ReasonCode != ManifestDigestMismatch {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	})
}

func lifecycleCommand(base Command, operation RegistryOperation, suffix, digest string, expected uint64) Command {
	base.OperationID = "0198e300-1000-7000-8000-000000000" + suffix
	base.IdempotencyKey = digestBytes([]byte("lifecycle-" + suffix))
	base.Operation = operation
	base.MappingDigest = digest
	base.ExpectedRegistryRevision = expected
	base.SignedMapping = nil
	return base
}

func assertLifecycleReceipt(t *testing.T, service *Service, command Command, status Status, reason Reason, revision uint64) Receipt {
	t.Helper()
	receipt, err := service.Execute(context.Background(), command, nil)
	if err != nil || receipt.Status != status || receipt.ReasonCode != reason {
		t.Fatalf("operation=%s receipt=%+v err=%v", command.Operation, receipt, err)
	}
	outcome, exists, err := service.dependencies.Store.LoadOutcome(context.Background(), receipt.OutcomeDigest)
	if err != nil || !exists || outcome.RegistryRevision != revision {
		t.Fatalf("operation=%s outcome=%+v exists=%v err=%v", command.Operation, outcome, exists, err)
	}
	return receipt
}

func assertCurrentSnapshot(t *testing.T, store *memoryMappingStore, current, predecessor string, revision uint64, revoked bool) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.snapshots) != 1 {
		t.Fatalf("snapshots=%+v", store.snapshots)
	}
	snapshot := store.snapshots[0]
	if snapshot.CurrentManifestDigest != current || snapshot.PredecessorManifestDigest != predecessor ||
		snapshot.Revision != revision || snapshot.CurrentRevoked != revoked {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
