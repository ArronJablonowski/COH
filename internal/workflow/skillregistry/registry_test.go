package skillregistry

import (
	"context"
	"testing"
	"time"
)

func TestPromotionResolutionRollbackAndRevocation(t *testing.T) {
	fixture := newFixture(t)
	store := newMemoryStore()
	auditor := newMemoryAuditor()
	registry, err := New(store, auditor, fixedClock{fixture.now})
	if err != nil {
		t.Fatal(err)
	}

	manifestV1 := fixture.manifest(t, "1.0.0", "", "2")
	envelopeV1, digestV1 := fixture.envelope(t, manifestV1)
	promoteV1 := fixture.changeRequest(t, "promote-v1", Promote, envelopeV1, digestV1, "", 0)
	stateV1, err := registry.Change(context.Background(), promoteV1)
	if err != nil {
		t.Fatal(err)
	}
	if stateV1.Status != Promoted || stateV1.CurrentManifestDigest != digestV1 ||
		stateV1.Revision != 1 || stateV1.PreviousManifestDigest != "" || store.commits != 1 ||
		auditor.count != 1 {
		t.Fatalf("unexpected initial state: %#v", stateV1)
	}
	replayed, err := registry.Change(context.Background(), promoteV1)
	if err != nil || replayed.ProvenanceDigest != stateV1.ProvenanceDigest ||
		store.commits != 1 || auditor.count != 1 {
		t.Fatalf("exact replay changed state: %#v %v", replayed, err)
	}

	resolved := resolveSkill(t, registry, fixture, digestV1, "resolve-v1")
	if resolved.SkillVersion != "1.0.0" || resolved.ContentDigest != manifestV1.ContentDigest ||
		resolved.ManifestDigest != digestV1 || len(resolved.Resources) != 1 ||
		resolved.ProvenanceDigest != stateV1.ProvenanceDigest || auditor.count != 2 {
		t.Fatalf("unexpected resolution: %#v", resolved)
	}
	resolved.Resources[0].Name = "mutated"
	resolved.Permissions[0] = "mutated"
	again := resolveSkill(t, registry, fixture, digestV1, "resolve-v1-again")
	if again.Resources[0].Name != "instructions" || again.Permissions[0] != "evidence.read" {
		t.Fatal("resolution exposed mutable registry state")
	}

	manifestV2 := fixture.manifest(t, "2.0.0", digestV1, "3")
	envelopeV2, digestV2 := fixture.envelope(t, manifestV2)
	promoteV2 := fixture.changeRequest(t, "promote-v2", Promote, envelopeV2, digestV2, digestV1, 1)
	stateV2, err := registry.Change(context.Background(), promoteV2)
	if err != nil {
		t.Fatal(err)
	}
	if stateV2.CurrentManifestDigest != digestV2 || stateV2.PreviousManifestDigest != digestV1 ||
		stateV2.Revision != 2 || stateV2.PreviousProvenanceDigest != stateV1.ProvenanceDigest {
		t.Fatalf("promotion lineage invalid: %#v", stateV2)
	}

	rollback := fixture.changeRequest(t, "rollback-v1", Rollback, nil, digestV1, digestV2, 2)
	rolledBack, err := registry.Change(context.Background(), rollback)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.CurrentManifestDigest != digestV1 || rolledBack.PreviousManifestDigest != digestV2 ||
		rolledBack.LastAction != Rollback || rolledBack.Revision != 3 {
		t.Fatalf("rollback invalid: %#v", rolledBack)
	}
	resolveSkill(t, registry, fixture, digestV1, "resolve-rollback")

	revoke := fixture.changeRequest(t, "revoke-v1", Revoke, nil, digestV1, digestV1, 3)
	revoked, err := registry.Change(context.Background(), revoke)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != Revoked || revoked.CurrentManifestDigest != digestV1 ||
		revoked.LastAction != Revoke || revoked.Revision != 4 {
		t.Fatalf("revocation invalid: %#v", revoked)
	}
	_, err = registry.Resolve(context.Background(), resolutionRequest(fixture, digestV1, "after-revoke"),
		accessDecision(fixture, digestV1, "after-revoke"),
		resolutionAuthority(fixture))
	if CodeOf(err) != Denied || Reason(err) != "promoted_version_mismatch" {
		t.Fatalf("revoked skill resolved: %v", err)
	}
}

func TestChangedReplayAndCrashRecovery(t *testing.T) {
	fixture := newFixture(t)
	store := newMemoryStore()
	store.lostResponse = true
	auditor := newMemoryAuditor()
	registry, _ := New(store, auditor, fixedClock{fixture.now})
	manifest := fixture.manifest(t, "1.0.0", "", "2")
	envelope, digest := fixture.envelope(t, manifest)
	request := fixture.changeRequest(t, "crash-promote", Promote, envelope, digest, "", 0)
	if _, err := registry.Change(context.Background(), request); CodeOf(err) != Unavailable {
		t.Fatalf("lost response was not indeterminate: %v", err)
	}
	if store.commits != 1 || auditor.count != 1 {
		t.Fatal("commit did not occur before simulated response loss")
	}

	restarted, _ := New(store, auditor, fixedClock{fixture.now})
	recovered, err := restarted.Change(context.Background(), request)
	if err != nil || recovered.CurrentManifestDigest != digest || store.commits != 1 || auditor.count != 1 {
		t.Fatalf("recovery was not exact and idempotent: %#v %v", recovered, err)
	}

	changed := fixture.changeRequest(t, "different-command", Revoke, nil, digest, digest, 1)
	changed.IdempotencyKey = request.IdempotencyKey
	if _, err := restarted.Change(context.Background(), changed); CodeOf(err) != Denied ||
		Reason(err) != "changed_replay" {
		t.Fatalf("changed replay accepted: %v", err)
	}
}

func resolveSkill(t *testing.T, registry *Controller, fixture testFixture, digest, id string) ResolvedSkill {
	t.Helper()
	result, err := registry.Resolve(context.Background(), resolutionRequest(fixture, digest, id),
		accessDecision(fixture, digest, id), resolutionAuthority(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func resolutionRequest(fixture testFixture, digest, id string) ResolveRequest {
	return ResolveRequest{
		SchemaVersion: ResolveSchemaVersion, ContractVersion: ContractVersion,
		RequestID: deterministicUUID("resolve", id), OrganizationID: testOrganization,
		TenantID: testTenant, CaseID: testCase, TaskID: testTask, ActorID: testConsumer,
		SkillName: "timeline_builder", ExpectedManifestDigest: digest,
		RequiredPermission: "evidence.read", PolicyDigest: testDigest("1"),
		Deadline: fixture.now.Add(time.Hour),
	}
}

func accessDecision(fixture testFixture, digest, id string) AccessDecision {
	value := AccessDecision{
		SchemaVersion: AccessSchemaVersion, ContractVersion: ContractVersion,
		DecisionID:   deterministicUUID("access", id),
		PolicyDigest: testDigest("1"), OrganizationID: testOrganization, TenantID: testTenant,
		CaseID: testCase, TaskID: testTask, ActorID: testConsumer, SkillName: "timeline_builder",
		ManifestDigest: digest, Permission: "evidence.read", Outcome: "allow", Revision: 1,
		IssuedAt: fixture.now.Add(-time.Minute), ExpiresAt: fixture.now.Add(time.Hour),
	}
	value.DecisionDigest, _ = accessDecisionDigest(value)
	return value
}

func resolutionAuthority(fixture testFixture) ResolutionAuthority {
	return ResolutionAuthority{Publisher: fixture.publisher,
		Reviewers: []SigningAuthority{fixture.reviewer}, Review: fixture.review}
}
