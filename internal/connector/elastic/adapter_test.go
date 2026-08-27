package elastic

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var testNow = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type clientStub struct {
	identity ClusterIdentity
	receipt  CallReceipt
	resolved ResolveResult
	caps     FieldCapabilitiesResult
	err      error
	calls    []string
}

func (client *clientStub) Inspect(_ context.Context, binding CallBinding) (ClusterIdentity, CallReceipt, error) {
	client.calls = append(client.calls, binding.Operation)
	return client.identity, client.receipt, client.err
}

func (client *clientStub) Resolve(_ context.Context, request ResolveRequest) (ResolveResult, CallReceipt, error) {
	client.calls = append(client.calls, request.Binding.Operation)
	return client.resolved, client.receipt, client.err
}

func (client *clientStub) FieldCapabilities(_ context.Context, request FieldCapabilitiesRequest) (FieldCapabilitiesResult, CallReceipt, error) {
	client.calls = append(client.calls, request.Binding.Operation)
	return client.caps, client.receipt, client.err
}

func TestProbeAndDiscoverSchemaAreIdentityAndScopeBound(t *testing.T) {
	adapter, client, _ := testAdapter(t)
	capability, err := adapter.Probe(context.Background(), testScope(), testAuthority())
	if err != nil {
		t.Fatal(err)
	}
	value := capability.Value()
	if !value.Features.ReadOnly || !value.Features.SchemaDiscovery || value.SourceID != "elastic-prod" ||
		value.SourceIdentityDigest == "" {
		t.Fatalf("capability=%+v", value)
	}
	page, err := adapter.DiscoverSchema(context.Background(), testRequest(capability.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	pageValue := page.Value()
	if !pageValue.Complete || pageValue.NextCursor != nil || len(pageValue.Entries) != 2 ||
		pageValue.Entries[0].Name != "event_timestamp" || pageValue.Entries[0].Type != "timestamp" ||
		pageValue.Entries[1].Name != "source_ip" || pageValue.Entries[1].Type != "ip" {
		t.Fatalf("page=%+v", pageValue)
	}
	wantCalls := []string{"elastic.inspect", "elastic.inspect", "elastic.resolve", "elastic.field_caps"}
	if strings.Join(client.calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls=%v", client.calls)
	}
}

func TestConfigurationRejectsAmbientOrBroadSurfaces(t *testing.T) {
	base := testConfig()
	cases := map[string]func(*Config){
		"plaintext":       func(config *Config) { config.Endpoint = "http://elastic.example.test" },
		"base-path":       func(config *Config) { config.Endpoint = "https://elastic.example.test/proxy" },
		"remote-cluster":  func(config *Config) { config.Resources[0].Expression = "remote:logs-*" },
		"all-targets":     func(config *Config) { config.Resources[0].Expression = "*" },
		"hidden-targets":  func(config *Config) { config.Resources[0].Expression = ".security-*" },
		"wildcard-fields": func(config *Config) { config.Fields[0].VendorName = "*" },
		"unknown-version": func(config *Config) { config.QualifiedMinorVersions = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			config.Resources = append([]Resource(nil), base.Resources...)
			config.Fields = append([]Field(nil), base.Fields...)
			mutate(&config)
			if _, err := New(config, &clientStub{}, &fixedClock{testNow}); queryconnector.Code(err) != queryconnector.InvalidInput {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestDiscoveryFailsClosedOnIdentityReceiptAndTargetDrift(t *testing.T) {
	cases := map[string]struct {
		mutate func(*clientStub)
		code   queryconnector.ErrorCode
		reason string
	}{
		"cluster-substitution":   {func(client *clientStub) { client.identity.ClusterUUID = "other-cluster-uuid" }, queryconnector.Conflict, "elastic_cluster_identity_mismatch"},
		"transport-substitution": {func(client *clientStub) { client.receipt.TransportDigest = testDigest("9") }, queryconnector.Denied, "elastic_receipt_invalid"},
		"target-substitution":    {func(client *clientStub) { client.caps.Indices = []string{"logs-security-000002"} }, queryconnector.Conflict, "elastic_field_caps_target_drift"},
		"hidden-target":          {func(client *clientStub) { client.resolved.Indices[0].Name = ".security-7" }, queryconnector.Denied, "elastic_resolved_target_invalid"},
		"data-stream": {func(client *clientStub) {
			client.resolved.DataStreams = []ResolvedDataStream{{Name: "logs-security", BackingIndices: []string{".ds-logs-security-1"}}}
		}, queryconnector.Unsupported, "elastic_data_stream_unsupported"},
		"type-conflict":  {func(client *clientStub) { client.caps.Fields = append(client.caps.Fields, client.caps.Fields[0]) }, queryconnector.Unsupported, "elastic_field_type_conflict"},
		"field-widening": {func(client *clientStub) { client.caps.Fields[0].Name = "secret.value" }, queryconnector.Denied, "elastic_field_scope_widened"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			adapter, client, _ := testAdapter(t)
			capability, err := adapter.Probe(context.Background(), testScope(), testAuthority())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(client)
			_, err = adapter.LoadSchema(context.Background(), testRequest(capability.Digest()))
			if queryconnector.Code(err) != test.code || queryconnector.Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", queryconnector.Code(err), queryconnector.Reason(err), err)
			}
		})
	}
}

func TestDiscoveryRejectsStaleOrWidenedCapability(t *testing.T) {
	adapter, _, clock := testAdapter(t)
	capability, err := adapter.Probe(context.Background(), testScope(), testAuthority())
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(capability.Digest())
	request.Scope.ResourceIDs = []string{"other"}
	if _, err := adapter.LoadSchema(context.Background(), request); queryconnector.Reason(err) != "elastic_resource_not_allowed" {
		t.Fatalf("scope widening err=%v", err)
	}
	clock.now = testNow.Add(11 * time.Minute)
	if _, err := adapter.LoadSchema(context.Background(), testRequest(capability.Digest())); queryconnector.Reason(err) != "elastic_capability_stale" {
		t.Fatalf("stale capability err=%v", err)
	}
}

func TestSchemaPaginationIsOpaqueBoundedAndReplayIdempotent(t *testing.T) {
	adapter, _, _ := testAdapter(t)
	adapter.config.MaximumSchemaEntriesPerPage = 1
	capability, err := adapter.Probe(context.Background(), testScope(), testAuthority())
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(capability.Digest())
	first, err := adapter.LoadSchema(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	firstValue := first.Value()
	if firstValue.Complete || firstValue.NextCursor == nil || len(firstValue.Entries) != 1 ||
		strings.Contains(string(first.CanonicalBytes()), "logs-security") {
		t.Fatalf("first=%+v", firstValue)
	}
	request.Cursor = firstValue.NextCursor
	second, err := adapter.LoadSchema(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, replayErr := adapter.LoadSchema(context.Background(), request)
	if replayErr != nil || replayed.Digest() != second.Digest() || !second.Value().Complete ||
		second.Value().SchemaDigest != firstValue.SchemaDigest {
		t.Fatalf("second=%+v replay=%s err=%v", second.Value(), replayed.Digest(), replayErr)
	}
	request.Authority.PolicyDecisionDigest = testDigest("9")
	if _, err := adapter.LoadSchema(context.Background(), request); queryconnector.Reason(err) != "elastic_schema_cursor_mismatch" {
		t.Fatalf("substituted cursor err=%v", err)
	}
}

func TestPublishedCapabilityFixtureUsesStrictQueryContract(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/elastic-discovery/v1/fixtures/capability.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	capability, err := queryconnector.DecodeCapability(context.Background(), input)
	if err != nil || capability.Value().SourceID != "elastic-prod" || !capability.Value().Features.ReadOnly {
		t.Fatalf("capability=%+v err=%v", capability.Value(), err)
	}
	for _, forbidden := range []string{"credential", "api_key", "authorization", "vendor_body", "secret"} {
		if strings.Contains(strings.ToLower(string(input)), forbidden) {
			t.Fatalf("published capability contains %q", forbidden)
		}
	}
}

func testAdapter(t testing.TB) (*Adapter, *clientStub, *fixedClock) {
	t.Helper()
	client := &clientStub{
		identity: ClusterIdentity{ClusterUUID: "cluster-uuid-1234", Version: "8.19.2", BuildFlavor: "default", BuildHash: "abc123"},
		receipt: CallReceipt{RequestDigest: testDigest("1"), ResponseDigest: testDigest("2"),
			LeaseDecisionDigest: testDigest("3"), TransportDigest: testDigest("4")},
		resolved: ResolveResult{Indices: []ResolvedTarget{{Name: "logs-security-000001"}}},
		caps: FieldCapabilitiesResult{Indices: []string{"logs-security-000001"}, Fields: []FieldCapability{
			{Name: "@timestamp", Type: "date", Searchable: true},
			{Name: "source.ip", Type: "ip", Searchable: true},
		}},
	}
	clock := &fixedClock{now: testNow}
	adapter, err := New(testConfig(), client, clock)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, client, clock
}

func testConfig() Config {
	return Config{SourceID: "elastic-prod", AdapterVersion: "elastic-1.0.0", Deployment: "self_managed",
		Endpoint: "https://elastic.example.test", ExpectedClusterUUID: "cluster-uuid-1234",
		ExpectedBuildFlavor: "default",
		MinimumMajorVersion: 8, MaximumMajorVersion: 9, QualifiedMinorVersions: []string{"8.19", "9.1"},
		TransportIdentityDigest: testDigest("4"),
		Resources:               []Resource{{ID: "securityevent", Expression: "logs-security-*"}},
		Fields:                  []Field{{VendorName: "@timestamp", SchemaName: "event_timestamp"}, {VendorName: "source.ip", SchemaName: "source_ip"}},
		HardLimits: queryconnector.Limits{MaximumRows: 1000, MaximumBytes: 1 << 20, MaximumDurationMillis: 60000,
			MaximumPages: 10, MaximumSlices: 4, MaximumCostMillionths: 1000000, RequestsPerMinute: 12},
		CapabilityLifetime: 10 * time.Minute, MaximumSchemaEntriesPerPage: 1024,
	}
}

func testScope() queryconnector.Scope {
	return queryconnector.Scope{OrganizationID: testID("1"), TenantID: testID("2"), CaseID: testID("3"),
		SourceID: "elastic-prod", ResourceIDs: []string{"securityevent"}}
}

func testAuthority() queryconnector.AuthorityBinding {
	return queryconnector.AuthorityBinding{ActorID: testID("4"), AuthorizationDigest: testDigest("5"),
		PolicyDecisionDigest: testDigest("6"), AuditReservationDigest: testDigest("7")}
}

func testRequest(capability string) queryconnector.SchemaRequest {
	return queryconnector.SchemaRequest{RequestID: testID("5"), Scope: testScope(), Authority: testAuthority(),
		CapabilityDigest: capability, Limits: queryconnector.Limits{MaximumRows: 100, MaximumBytes: 100000,
			MaximumDurationMillis: 5000, MaximumPages: 2, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2}}
}

func testID(value string) string { return "018f1f2e-7a6b-7c8d-8e9f-00000000000" + value }
func testDigest(value string) string {
	return "sha256:" + strings.Repeat("0", 63) + value
}
