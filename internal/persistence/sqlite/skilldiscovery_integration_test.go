package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/skilldiscovery"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

const (
	discoveryOrg     = "0198d6c4-3001-7001-8001-000000000001"
	discoveryTenant  = "0198d6c4-3002-7002-8002-000000000002"
	discoveryCase    = "0198d6c4-3003-7003-8003-000000000003"
	discoveryTask    = "0198d6c4-3004-7004-8004-000000000004"
	discoveryActor   = "0198d6c4-3005-7005-8005-000000000005"
	discoveryOwner   = "0198d6c4-3006-7006-8006-000000000006"
	discoveryReview  = "0198d6c4-3007-7007-8007-000000000007"
	discoveryRequest = "0198d6c4-3008-7008-8008-000000000008"
)

type discoveryClock struct{ value time.Time }

func (clock discoveryClock) Now() time.Time { return clock.value }

type discoveryCatalog struct{ snapshot skillregistry.CatalogSnapshot }

func (catalog discoveryCatalog) LoadCatalog(context.Context, string, string) (skillregistry.CatalogSnapshot, error) {
	return catalog.snapshot, nil
}

type discoveryRegistry struct{ result skillregistry.ResolvedSkill }

func (registry discoveryRegistry) Resolve(_ context.Context, _ skillregistry.ResolveRequest,
	_ skillregistry.AccessDecision, _ skillregistry.ResolutionAuthority) (skillregistry.ResolvedSkill, error) {
	result := registry.result
	result.Resources = append([]skillregistry.Resource(nil), result.Resources...)
	result.Permissions = append([]string(nil), result.Permissions...)
	return result, nil
}

type discoveryAuthority struct{ now time.Time }

func (authority discoveryAuthority) AuthorizeDiscovery(_ context.Context,
	request skilldiscovery.AuthorizationRequest) (skilldiscovery.Decision,
	skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error) {
	decision := skilldiscovery.Decision{SchemaVersion: skilldiscovery.DecisionSchemaVersion,
		ContractVersion: skilldiscovery.ContractVersion, DecisionID: discoveryUUID(request.SkillName),
		RequestID: request.RequestID, PolicyDigest: request.PolicyDigest, Case: request.Case,
		TaskID: request.TaskID, ActorID: request.ActorID, Phase: request.Phase,
		SkillName: request.SkillName, ManifestDigest: request.ManifestDigest,
		RequiredPermission: request.RequiredPermission, ResourceName: request.ResourceName,
		ResourceDigest: request.ResourceDigest, QueryDigest: request.QueryDigest,
		SnapshotDigest: request.SnapshotDigest, Cursor: request.Cursor, PageLimit: request.PageLimit,
		ParentResultDigest: request.ParentResultDigest, Deadline: request.Deadline,
		Outcome: "allow", Revision: 1,
		IssuedAt: authority.now.Add(-time.Minute), ExpiresAt: authority.now.Add(time.Hour)}
	decision.DecisionDigest, _ = skilldiscovery.DigestDecision(decision)
	return decision, skillregistry.AccessDecision{}, skillregistry.ResolutionAuthority{}, nil
}

type discoveryRetriever struct{}

func (discoveryRetriever) ResolveResource(context.Context,
	skilldiscovery.RetrievalRequest) (domain.ArtifactRef, error) {
	return domain.ArtifactRef{}, nil
}

type signedDiscoveryAuthority struct {
	now     time.Time
	fixture skillFixture
}

func (authority signedDiscoveryAuthority) AuthorizeDiscovery(_ context.Context,
	request skilldiscovery.AuthorizationRequest) (skilldiscovery.Decision,
	skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error) {
	decision, _, _, _ := discoveryAuthority{authority.now}.AuthorizeDiscovery(context.Background(), request)
	resolution := skillregistry.ResolutionAuthority{Publisher: authority.fixture.publisher,
		Reviewers: []skillregistry.SigningAuthority{authority.fixture.reviewer}, Review: authority.fixture.review}
	if request.SkillName == "" {
		return decision, skillregistry.AccessDecision{}, resolution, nil
	}
	access := skillregistry.AccessDecision{SchemaVersion: skillregistry.AccessSchemaVersion,
		ContractVersion: skillregistry.ContractVersion, DecisionID: discoveryUUID("access-" + request.SkillName),
		PolicyDigest: request.PolicyDigest, OrganizationID: request.Case.OrganizationID,
		TenantID: request.Case.TenantID, CaseID: request.Case.CaseID, TaskID: request.TaskID,
		ActorID: request.ActorID, SkillName: request.SkillName, ManifestDigest: request.ManifestDigest,
		Permission: request.RequiredPermission, Outcome: "allow", Revision: 1,
		IssuedAt: authority.now.Add(-time.Minute), ExpiresAt: authority.now.Add(time.Hour)}
	access.DecisionDigest, _ = skillregistry.DigestAccessDecision(access)
	return decision, access, resolution, nil
}

type signedDiscoveryRetriever struct{}

func (signedDiscoveryRetriever) ResolveResource(_ context.Context,
	request skilldiscovery.RetrievalRequest) (domain.ArtifactRef, error) {
	return domain.ArtifactRef{Digest: request.Resource.Digest, MediaType: request.Resource.MediaType,
		Classification: request.Resource.Classification, Length: request.Resource.Length}, nil
}

func TestSkillDiscoveryReplaySurvivesSQLiteCloseAndReopen(t *testing.T) {
	now := time.Date(2026, 8, 26, 22, 0, 0, 0, time.UTC)
	manifest, provenance := discoveryDigest("manifest"), discoveryDigest("provenance")
	catalog := discoveryCatalog{skillregistry.CatalogSnapshot{SchemaVersion: skillregistry.CatalogSchemaVersion,
		ContractVersion: skillregistry.ContractVersion, OrganizationID: discoveryOrg,
		TenantID: discoveryTenant, Entries: []skillregistry.PromotedSkillRef{{SkillName: "timeline_builder",
			ManifestDigest: manifest, StateRevision: 1, ProvenanceDigest: provenance}},
		SnapshotDigest: discoveryDigest("snapshot"), UpdatedAt: now, Revision: 1}}
	registry := discoveryRegistry{skillregistry.ResolvedSkill{SkillName: "timeline_builder",
		SkillVersion: "1.0.0", ManifestDigest: manifest, ContentDigest: discoveryDigest("content"),
		Resources: []skillregistry.Resource{{Name: "instructions", Digest: discoveryDigest("resource"),
			MediaType: "text/markdown", Classification: "internal", Length: 128}},
		Permissions:  []string{"evidence.read"},
		OwnerActorID: discoveryOwner, ReviewID: discoveryReview, ReviewRevision: 1,
		ProvenanceDigest: provenance}}
	request := skilldiscovery.SearchRequest{SchemaVersion: skilldiscovery.SearchSchemaVersion,
		ContractVersion: skilldiscovery.ContractVersion, RequestID: discoveryRequest,
		IdempotencyKey: "sqlite-discovery-search", Case: domain.CaseRef{OrganizationID: discoveryOrg,
			TenantID: discoveryTenant, CaseID: discoveryCase}, TaskID: discoveryTask,
		ActorID: discoveryActor, PolicyDigest: discoveryDigest("policy"),
		RequiredPermission: "evidence.read", Limit: 1, Deadline: now.Add(time.Hour)}

	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "coh.sqlite3")
	driver := openDiscoverySQLite(t, path, backup, now)
	controller := composeDiscovery(t, driver, catalog, registry, now)
	first, err := controller.Search(context.Background(), request)
	if err != nil || first.Replayed || len(first.Skills) != 1 {
		t.Fatalf("initial discovery failed: %#v %v", first, err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	driver = openDiscoverySQLite(t, path, backup, now)
	t.Cleanup(func() { _ = driver.Close() })
	controller = composeDiscovery(t, driver, catalog, registry, now)
	replayed, err := controller.Search(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.ResultDigest != first.ResultDigest {
		t.Fatalf("durable replay failed: %#v %v", replayed, err)
	}
	changed := request
	changed.Query = "timeline"
	if _, err := controller.Search(context.Background(), changed); skilldiscovery.CodeOf(err) != skilldiscovery.Denied {
		t.Fatalf("changed durable replay accepted: %v", err)
	}
}

func TestProgressiveDiscoveryRevalidatesSignedRegistryAndRevocation(t *testing.T) {
	fixture := newSkillFixture()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openDiscoverySQLite(t, filepath.Join(root, "coh.sqlite3"), backup, fixture.now)
	t.Cleanup(func() { _ = driver.Close() })
	registry, catalog := composeSkillRegistry(t, driver, fixture)
	envelope, manifestDigest := fixture.envelope(t, fixture.manifest())
	state, err := registry.Change(context.Background(), fixture.promotion(t, envelope, manifestDigest))
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := skilldiscovery.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := skilldiscovery.New(catalog, registry,
		signedDiscoveryAuthority{fixture.now, fixture}, signedDiscoveryRetriever{}, store,
		discoveryClock{fixture.now})
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.CaseRef{OrganizationID: skillOrg, TenantID: skillTenant, CaseID: skillCase}
	search := skilldiscovery.SearchRequest{SchemaVersion: skilldiscovery.SearchSchemaVersion,
		ContractVersion: skilldiscovery.ContractVersion, RequestID: discoveryUUID("signed-search"),
		IdempotencyKey: "signed-discovery-search", Case: scope, TaskID: skillTask,
		ActorID: skillConsumer, PolicyDigest: skillDigest("discovery-policy"),
		RequiredPermission: "evidence.read", Limit: 8, Deadline: fixture.now.Add(time.Hour)}
	page, err := controller.Search(context.Background(), search)
	if err != nil || len(page.Skills) != 1 || page.Skills[0].ManifestDigest != manifestDigest ||
		page.Skills[0].ProvenanceDigest != state.ProvenanceDigest {
		t.Fatalf("signed compact search failed: %#v %v", page, err)
	}
	detail := skilldiscovery.DetailRequest{SchemaVersion: skilldiscovery.DetailSchemaVersion,
		ContractVersion: skilldiscovery.ContractVersion, RequestID: discoveryUUID("signed-detail"),
		IdempotencyKey: "signed-discovery-detail", Case: scope, TaskID: skillTask,
		ActorID: skillConsumer, PolicyDigest: search.PolicyDigest, RequiredPermission: search.RequiredPermission,
		SkillName: "timeline_builder", ExpectedManifestDigest: manifestDigest,
		SearchIdempotencyKey: search.IdempotencyKey, ExpectedSearchResultDigest: page.ResultDigest,
		Deadline: search.Deadline}
	expanded, err := controller.Detail(context.Background(), detail)
	if err != nil || len(expanded.Resources) != 1 || expanded.ProvenanceDigest != state.ProvenanceDigest {
		t.Fatalf("signed detail failed: %#v %v", expanded, err)
	}
	resource := skilldiscovery.ResourceRequest{SchemaVersion: skilldiscovery.ResourceSchemaVersion,
		ContractVersion: skilldiscovery.ContractVersion, RequestID: discoveryUUID("signed-resource"),
		IdempotencyKey: "signed-discovery-resource", Case: scope, TaskID: skillTask,
		ActorID: skillConsumer, PolicyDigest: search.PolicyDigest, RequiredPermission: search.RequiredPermission,
		SkillName: detail.SkillName, ExpectedManifestDigest: detail.ExpectedManifestDigest,
		ResourceName: expanded.Resources[0].Name, ResourceDigest: expanded.Resources[0].Digest,
		DetailIdempotencyKey: detail.IdempotencyKey, ExpectedDetailResultDigest: expanded.ResultDigest,
		Deadline: search.Deadline}
	resolved, err := controller.Resource(context.Background(), resource)
	if err != nil || resolved.Artifact.Digest != expanded.Resources[0].Digest {
		t.Fatalf("signed resource resolution failed: %#v %v", resolved, err)
	}
	if _, err := registry.Change(context.Background(), fixture.revocation(t, manifestDigest, state.Revision)); err != nil {
		t.Fatal(err)
	}
	search.RequestID = discoveryUUID("after-revoke-search")
	search.IdempotencyKey = "after-revoke-search"
	page, err = controller.Search(context.Background(), search)
	if err != nil || len(page.Skills) != 0 {
		t.Fatalf("revoked skill remained in compact search: %#v %v", page, err)
	}
	detail.RequestID = discoveryUUID("after-revoke-detail")
	detail.IdempotencyKey = "after-revoke-detail"
	if _, err := controller.Detail(context.Background(), detail); skilldiscovery.CodeOf(err) != skilldiscovery.Denied {
		t.Fatalf("revoked detail expansion succeeded: %v", err)
	}
}

func composeDiscovery(t *testing.T, driver *sqlite.Store, catalog discoveryCatalog,
	registry discoveryRegistry, now time.Time) *skilldiscovery.Controller {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := skilldiscovery.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := skilldiscovery.New(catalog, registry, discoveryAuthority{now},
		discoveryRetriever{}, store, discoveryClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func openDiscoverySQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	driver, err := sqlite.Open(context.Background(), sqlite.Config{Path: path,
		BackupDirectory: backup, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func discoveryDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func discoveryUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
