package schemacache

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var baseTime = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Add(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type loaderFunc func(context.Context, queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error)

func (loader loaderFunc) LoadSchema(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
	return loader(ctx, request)
}

func TestMissHitPreservesImmutableProvenance(t *testing.T) {
	clock := &testClock{now: baseTime}
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		calls.Add(1)
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	cache := newTestCache(t, clock, loader, Config{MaximumEntries: 4, MaximumTotalBytes: 1 << 20,
		MaximumEntryBytes: 1 << 18, TTL: time.Minute, LoadTimeout: time.Second})
	request := validRequest(t, "1", "securityevent")
	loaded, err := cache.Get(context.Background(), request)
	if err != nil || loaded.Hit() || calls.Load() != 1 || !digestPattern.MatchString(loaded.IdentityDigest()) {
		t.Fatalf("loaded=%+v calls=%d err=%v", loaded, calls.Load(), err)
	}
	pageBytes := loaded.Page().CanonicalBytes()
	pageBytes[0] = '['
	pageValue := loaded.Page().Value()
	pageValue.Entries[0].Name = "changed"
	hit, err := cache.Get(context.Background(), request)
	if err != nil || !hit.Hit() || calls.Load() != 1 || hit.IdentityDigest() != loaded.IdentityDigest() ||
		hit.Page().CanonicalBytes()[0] != '{' || hit.Page().Value().Entries[0].Name != "event_id" ||
		hit.Page().Value().ProvenanceDigest != digest("7") {
		t.Fatalf("hit=%+v calls=%d err=%v", hit, calls.Load(), err)
	}
}

func TestCanonicalIdentityFixture(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/schema-cache/v1/fixtures/entry-identity.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	identity, err := digestValue(identityDigestDomain, value)
	if err != nil || identity != "sha256:dd5207492cd0a8a5ad7a7f584b10e88c61125401b742c18086b6318017b6de2c" {
		t.Fatalf("identity=%s err=%v", identity, err)
	}
	if value["schema_version"] != SchemaVersion || value["contract_version"] != ContractVersion {
		t.Fatalf("fixture version=%v contract=%v", value["schema_version"], value["contract_version"])
	}
}

func TestExactKeyIsolationAndScopedInvalidation(t *testing.T) {
	clock := &testClock{now: baseTime}
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		calls.Add(1)
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	cache := newTestCache(t, clock, loader, testConfig())
	first := validRequest(t, "1", "securityevent")
	second := validRequest(t, "2", "signinevent")
	second.SchemaRequest.Scope.TenantID = id("9")
	if _, err := cache.Get(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(context.Background(), second); err != nil || calls.Load() != 2 {
		t.Fatalf("isolated load calls=%d err=%v", calls.Load(), err)
	}
	target := Invalidation{OrganizationID: first.SchemaRequest.Scope.OrganizationID,
		TenantID: first.SchemaRequest.Scope.TenantID, SourceID: first.SchemaRequest.Scope.SourceID}
	if err := cache.Invalidate(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(context.Background(), first); err != nil || calls.Load() != 3 {
		t.Fatalf("invalidated calls=%d err=%v", calls.Load(), err)
	}
	if snapshot, err := cache.Get(context.Background(), second); err != nil || !snapshot.Hit() || calls.Load() != 3 {
		t.Fatalf("unrelated entry calls=%d hit=%t err=%v", calls.Load(), snapshot.Hit(), err)
	}
	if err := cache.Invalidate(context.Background(), target); err != nil {
		t.Fatalf("idempotent invalidation err=%v", err)
	}
}

func TestConcurrentLoadIsCoalesced(t *testing.T) {
	clock := &testClock{now: baseTime}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return queryconnector.ValidatedSchemaPage{}, ctx.Err()
		case <-release:
			return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
		}
	})
	cache := newTestCache(t, clock, loader, testConfig())
	request := validRequest(t, "1", "securityevent")
	results := make(chan error, 12)
	for range 12 {
		go func() { _, err := cache.Get(context.Background(), request); results <- err }()
	}
	<-started
	close(release)
	for range 12 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("loader calls=%d", calls.Load())
	}
}

func TestTTLAndCapabilityExpiryNeverServeStale(t *testing.T) {
	clock := &testClock{now: baseTime}
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		if calls.Add(1) > 1 {
			return queryconnector.ValidatedSchemaPage{}, queryconnector.NewError(queryconnector.Unavailable, "vendor_unavailable", nil)
		}
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	cache := newTestCache(t, clock, loader, Config{MaximumEntries: 4, MaximumTotalBytes: 1 << 20,
		MaximumEntryBytes: 1 << 18, TTL: time.Second, LoadTimeout: time.Second})
	request := validRequest(t, "1", "securityevent")
	if _, err := cache.Get(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	if _, err := cache.Get(context.Background(), request); Code(err) != Unavailable || Reason(err) != "loader_unavailable" {
		t.Fatalf("stale fallback err=%v", err)
	}
	clock.Add(2 * time.Hour)
	if _, err := cache.Get(context.Background(), request); Code(err) != Denied || Reason(err) != "capability_stale" {
		t.Fatalf("expired capability err=%v", err)
	}
}

func TestLRUEvictionHonorsEntryBound(t *testing.T) {
	clock := &testClock{now: baseTime}
	var calls atomic.Int32
	loader := loaderFunc(func(ctx context.Context, request queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error) {
		calls.Add(1)
		return schemaPage(t, ctx, request, request.Scope.ResourceIDs[0]), nil
	})
	config := testConfig()
	config.MaximumEntries = 2
	cache := newTestCache(t, clock, loader, config)
	one, two, three := validRequest(t, "1", "alpha"), validRequest(t, "2", "bravo"), validRequest(t, "3", "charlie")
	for _, request := range []Request{one, two} {
		if _, err := cache.Get(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cache.Get(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(context.Background(), three); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := cache.Get(context.Background(), one); err != nil || !snapshot.Hit() {
		t.Fatalf("recent entry evicted err=%v", err)
	}
	if snapshot, err := cache.Get(context.Background(), two); err != nil || snapshot.Hit() || calls.Load() != 4 {
		t.Fatalf("old entry retained hit=%t calls=%d err=%v", snapshot.Hit(), calls.Load(), err)
	}
}

func newTestCache(t *testing.T, clock Clock, loader Loader, config Config) *Cache {
	t.Helper()
	cache, err := New(config, loader, clock)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func testConfig() Config {
	return Config{MaximumEntries: 8, MaximumTotalBytes: 1 << 20, MaximumEntryBytes: 1 << 18,
		TTL: time.Minute, LoadTimeout: time.Second}
}

func validRequest(t *testing.T, suffix, resource string) Request {
	t.Helper()
	capabilityValue := queryconnector.CapabilitySnapshot{SchemaVersion: queryconnector.CapabilitySchemaVersion,
		ContractVersion: queryconnector.ContractVersion, SnapshotID: id("8"), SourceID: "sentinel-prod",
		AdapterVersion: "sentinel-1.0.0", ObservedAt: baseTime.Add(-time.Minute).Format(timestampLayout),
		ValidUntil: baseTime.Add(time.Hour).Format(timestampLayout), QueryLanguages: []string{"kql"},
		Features: queryconnector.Features{ReadOnly: true, SchemaDiscovery: true, Validation: true},
		HardLimits: queryconnector.Limits{MaximumRows: 1000, MaximumBytes: 1048576, MaximumDurationMillis: 60000,
			MaximumPages: 10, MaximumSlices: 4, MaximumCostMillionths: 1000000, RequestsPerMinute: 12},
		SourceIdentityDigest: digest("5")}
	capabilityBytes, _ := json.Marshal(capabilityValue)
	capability, err := queryconnector.DecodeCapability(context.Background(), capabilityBytes)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Capability: capability, SchemaRequest: queryconnector.SchemaRequest{RequestID: id(suffix),
		Scope: queryconnector.Scope{OrganizationID: id("a"), TenantID: id("b"), CaseID: id("c"),
			SourceID: "sentinel-prod", ResourceIDs: []string{resource}},
		Authority: queryconnector.AuthorityBinding{ActorID: id("d"), AuthorizationDigest: digest("1"),
			PolicyDecisionDigest: digest("2"), AuditReservationDigest: digest("3")}, CapabilityDigest: capability.Digest(),
		Limits: queryconnector.Limits{MaximumRows: 100, MaximumBytes: 10000, MaximumDurationMillis: 5000,
			MaximumPages: 2, MaximumSlices: 1, MaximumCostMillionths: 100, RequestsPerMinute: 2}}}
}

func schemaPage(t *testing.T, ctx context.Context, request queryconnector.SchemaRequest, resource string) queryconnector.ValidatedSchemaPage {
	t.Helper()
	value := queryconnector.SchemaPage{SchemaVersion: queryconnector.SchemaSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, RequestID: request.RequestID, SchemaDigest: digest("6"),
		Entries:  []queryconnector.SchemaEntry{{ResourceID: resource, Name: "event_id", Type: "string"}},
		Complete: true, ProvenanceDigest: digest("7")}
	encoded, _ := json.Marshal(value)
	page, err := queryconnector.DecodeSchemaPage(ctx, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func id(value string) string { return "018f1f2e-7a6b-7c8d-8e9f-00000000000" + value }
func digest(value string) string {
	return "sha256:" + strings.Repeat("0", 63) + value
}
