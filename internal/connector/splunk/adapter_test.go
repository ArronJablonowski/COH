package splunk

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/domain/schemacache"
)

func TestAdapterProbeAndDiscoveryAreQualifiedScopedAndSecretFree(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	capabilityValue := capability.Value()
	if capabilityValue.SourceID != "splunk-prod" || !capabilityValue.Features.ReadOnly ||
		!capabilityValue.Features.SchemaDiscovery || !capabilityValue.Features.Validation || !capabilityValue.Features.Polling ||
		!capabilityValue.Features.Paging || !capabilityValue.Features.Cancellation || !capabilityValue.Features.Statistics ||
		!slices.Equal(capabilityValue.QueryLanguages, []string{"spl"}) {
		t.Fatalf("capability=%+v", capabilityValue)
	}
	page, err := adapter.DiscoverSchema(context.Background(), splunkSchemaRequest(capability.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	value := page.Value()
	if !value.Complete || value.NextCursor != nil || len(value.Entries) != 2 ||
		value.Entries[0] != (queryconnector.SchemaEntry{ResourceID: "security-events", Name: "event.time", Type: "timestamp"}) ||
		value.Entries[1] != (queryconnector.SchemaEntry{ResourceID: "security-events", Name: "source.ip", Type: "ip", Nullable: true}) {
		t.Fatalf("page=%+v", value)
	}
	serialized := strings.ToLower(string(page.CanonicalBytes()))
	for _, forbidden := range []string{"_time", "src_ip", "broker-token", "authorization", "vendor_body", "sid"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("schema exposes %q: %s", forbidden, serialized)
		}
	}
	wantCalls := []string{"splunk.server_info", "splunk.current_context", "splunk.indexes", "splunk.fields"}
	if !slices.Equal(client.operations[2:], wantCalls) {
		t.Fatalf("adapter calls=%v", client.operations)
	}
}

func TestAdapterRejectsTruncationDriftAndDeclaredTypeConflict(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*qualificationClientStub)
		code   queryconnector.ErrorCode
		reason string
	}{
		{"index truncation", func(client *qualificationClientStub) { client.indexes.Truncated = true }, queryconnector.Unsupported, "splunk_index_inventory_truncated"},
		{"field truncation", func(client *qualificationClientStub) { client.fields.Truncated = true }, queryconnector.Unsupported, "splunk_field_inventory_truncated"},
		{"missing index", func(client *qualificationClientStub) { client.indexes.Names = []string{"other"} }, queryconnector.Conflict, "splunk_configured_index_missing"},
		{"missing field", func(client *qualificationClientStub) { client.fields.Fields = client.fields.Fields[:1] }, queryconnector.Conflict, "splunk_configured_field_missing"},
		{"indexing conflict", func(client *qualificationClientStub) { client.fields.Fields[0].Indexed = false }, queryconnector.Unsupported, "splunk_field_indexing_conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, client, _ := splunkTestAdapter(t, 256)
			capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
				splunkTestBinding("splunk.server_info").Authority)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(client)
			_, err = adapter.DiscoverSchema(context.Background(), splunkSchemaRequest(capability.Digest()))
			if queryconnector.Code(err) != test.code || queryconnector.Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", queryconnector.Code(err), queryconnector.Reason(err), err)
			}
		})
	}
}

func TestAdapterOpaquePaginationReplayAndScopeBinding(t *testing.T) {
	adapter, _, _ := splunkTestAdapter(t, 1)
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := splunkSchemaRequest(capability.Digest())
	first, err := adapter.DiscoverSchema(context.Background(), request)
	if err != nil || first.Value().Complete || first.Value().NextCursor == nil || len(first.Value().Entries) != 1 {
		t.Fatalf("first=%+v err=%v", first.Value(), err)
	}
	request.Cursor = first.Value().NextCursor
	second, err := adapter.DiscoverSchema(context.Background(), request)
	replayed, replayErr := adapter.DiscoverSchema(context.Background(), request)
	if err != nil || replayErr != nil || !second.Value().Complete || replayed.Digest() != second.Digest() ||
		second.Value().SchemaDigest != first.Value().SchemaDigest {
		t.Fatalf("second=%+v replay=%+v err=%v/%v", second.Value(), replayed.Value(), err, replayErr)
	}
	request.Authority.PolicyDecisionDigest = splunkTestDigest("9")
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "splunk_schema_cursor_mismatch" {
		t.Fatalf("cursor substitution err=%v", err)
	}
}

func TestAdapterRejectsLiveQualificationDrift(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.current.Capabilities = []string{"search"}
	if _, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority); queryconnector.Reason(err) != "splunk_qualification_drift" {
		t.Fatalf("drift err=%v", err)
	}
}

func TestAdapterSchemaCacheCoalescesQualifiedReplay(t *testing.T) {
	adapter, client, clock := splunkTestAdapter(t, 256)
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := schemacache.New(schemacache.Config{MaximumEntries: 8, MaximumTotalBytes: 1 << 20,
		MaximumEntryBytes: 1 << 20, TTL: time.Minute, LoadTimeout: time.Second}, adapter, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := schemacache.Request{SchemaRequest: splunkSchemaRequest(capability.Digest()), Capability: capability}
	first, err := cache.Get(context.Background(), request)
	if err != nil || first.Hit() {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	calls := len(client.operations)
	second, err := cache.Get(context.Background(), request)
	if err != nil || !second.Hit() || second.IdentityDigest() != first.IdentityDigest() || len(client.operations) != calls {
		t.Fatalf("second=%+v calls=%d/%d err=%v", second, calls, len(client.operations), err)
	}
}

func TestAdapterCancellationOutageRecoveryAndStaleness(t *testing.T) {
	adapter, client, clock := splunkTestAdapter(t, 256)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	calls := len(client.operations)
	if _, err := adapter.Probe(canceled, splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority); queryconnector.Code(err) != queryconnector.Canceled || len(client.operations) != calls {
		t.Fatalf("cancel err=%v calls=%v", err, client.operations)
	}
	client.err = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
	if _, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("outage err=%v", err)
	}
	client.err = nil
	capability, err := adapter.Probe(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatalf("recovery err=%v", err)
	}
	clock.now = splunkTestNow.Add(11 * time.Minute)
	if _, err := adapter.DiscoverSchema(context.Background(), splunkSchemaRequest(capability.Digest())); queryconnector.Reason(err) != "splunk_capability_stale" {
		t.Fatalf("stale err=%v", err)
	}
}

func splunkTestAdapter(t testing.TB, pageSize int) (*Adapter, *qualificationClientStub, *splunkFixedClock) {
	t.Helper()
	config, err := DecodeConfig(mustRead(t.(*testing.T), "fixtures/config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	config.MaximumSchemaEntriesPerPage = pageSize
	receipts := []CallReceipt{
		{RequestDigest: splunkTestDigest("1"), ResponseDigest: splunkTestDigest("2"), LeaseDecisionDigest: splunkTestDigest("3"), TransportDigest: config.TransportIdentityDigest},
		{RequestDigest: splunkTestDigest("4"), ResponseDigest: splunkTestDigest("5"), LeaseDecisionDigest: splunkTestDigest("6"), TransportDigest: config.TransportIdentityDigest},
	}
	client := &qualificationClientStub{identity: ServerIdentity{GUID: config.ExpectedServerGUID, ProductType: "enterprise",
		Version: "10.0.0", Build: "example-build", ServerRoles: []string{"search_head"}},
		current: CurrentContext{Capabilities: []string{"get_metadata", "search"}}, indexes: IndexInventory{Names: []string{"security"}},
		fields: RegisteredFieldInventory{Fields: []RegisteredField{{Name: "_time", Indexed: true}, {Name: "src_ip"}}}, receipts: receipts}
	clock := &splunkFixedClock{now: splunkTestNow}
	qualifier, err := NewQualifier(config, client, clock)
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := qualifier.Qualify(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(config, client, qualification, clock)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, client, clock
}

func splunkSchemaRequest(capability string) queryconnector.SchemaRequest {
	binding := splunkTestBinding("splunk.indexes")
	return queryconnector.SchemaRequest{RequestID: "018f1f2e-7a6b-7c8d-8e9f-000000000105", Scope: binding.Scope,
		Authority: binding.Authority, CapabilityDigest: capability, Limits: queryconnector.Limits{MaximumRows: 100,
			MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 2, MaximumSlices: 1,
			MaximumCostMillionths: 1000, RequestsPerMinute: 2}}
}
