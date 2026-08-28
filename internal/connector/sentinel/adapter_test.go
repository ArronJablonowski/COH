package sentinel

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterProbeAndSchemaAreQualifiedScopedAndSecretFree(t *testing.T) {
	adapter, client, config := sentinelTestAdapter(t, 256)
	binding := sentinelTestBinding(config)
	capability, err := adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	value := capability.Value()
	if !value.Features.ReadOnly || !value.Features.SchemaDiscovery || !value.Features.Validation || value.Features.Polling ||
		value.Features.Paging || value.Features.Cancellation || value.Features.Statistics ||
		!slices.Equal(value.QueryLanguages, []string{"kql"}) {
		t.Fatalf("capability=%+v", value)
	}
	page, err := adapter.DiscoverSchema(context.Background(), sentinelSchemaRequest(config, capability.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	pageValue := page.Value()
	if !pageValue.Complete || pageValue.NextCursor != nil || len(pageValue.Entries) != 4 ||
		pageValue.Entries[0] != (queryconnector.SchemaEntry{ResourceID: "security-events", Name: "event.action", Type: "string"}) ||
		pageValue.Entries[3] != (queryconnector.SchemaEntry{ResourceID: "signin-events", Name: "source.ip", Type: "ip", Nullable: true}) {
		t.Fatalf("page=%+v", pageValue)
	}
	serialized := strings.ToLower(string(page.CanonicalBytes()))
	for _, forbidden := range []string{"azureactivity", "signinlogs", "timegenerated", "ipaddress", "broker-token", "authorization", "resourcegroups"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("schema exposes %q: %s", forbidden, serialized)
		}
	}
	client.mu.Lock()
	calls := client.calls
	client.mu.Unlock()
	if calls != 3 { // qualification, probe, discovery
		t.Fatalf("metadata calls=%d", calls)
	}
}

func TestAdapterSchemaPaginationReplayCursorBindingAndCoalescing(t *testing.T) {
	adapter, client, config := sentinelTestAdapter(t, 1)
	binding := sentinelTestBinding(config)
	capability, err := adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	request := sentinelSchemaRequest(config, capability.Digest())
	var pages [16]queryconnector.ValidatedSchemaPage
	var errorsFound [16]error
	var wait sync.WaitGroup
	for index := range pages {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			pages[index], errorsFound[index] = adapter.DiscoverSchema(context.Background(), request)
		}(index)
	}
	wait.Wait()
	for index := range pages {
		if errorsFound[index] != nil || pages[index].Digest() != pages[0].Digest() || pages[index].Value().NextCursor == nil {
			t.Fatalf("page[%d]=%+v err=%v", index, pages[index].Value(), errorsFound[index])
		}
	}
	client.mu.Lock()
	calls := client.calls
	client.mu.Unlock()
	if calls != 3 { // exactly one coalesced discovery call
		t.Fatalf("metadata calls=%d", calls)
	}
	request.Cursor = pages[0].Value().NextCursor
	second, err := adapter.DiscoverSchema(context.Background(), request)
	replayed, replayErr := adapter.DiscoverSchema(context.Background(), request)
	if err != nil || replayErr != nil || second.Digest() != replayed.Digest() || second.Value().SchemaDigest != pages[0].Value().SchemaDigest {
		t.Fatalf("second=%+v replay=%+v err=%v/%v", second.Value(), replayed.Value(), err, replayErr)
	}
	request.Authority.PolicyDecisionDigest = sentinelTestDigest("9")
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "sentinel_capability_binding_mismatch" {
		t.Fatalf("authority substitution err=%v", err)
	}
}

func TestAdapterRejectsQualificationDriftExpiryAndBounds(t *testing.T) {
	adapter, client, config := sentinelTestAdapter(t, 256)
	binding := sentinelTestBinding(config)
	capability, err := adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	client.metadata.Tables[0].Columns[0].Type = "dynamic"
	client.metadata.Digest = metadataDigest(client.metadata)
	client.mu.Unlock()
	if _, err := adapter.DiscoverSchema(context.Background(), sentinelSchemaRequest(config, capability.Digest())); queryconnector.Reason(err) != "sentinel_metadata_drift" {
		t.Fatalf("drift err=%v", err)
	}
	adapter.clock.(*sentinelFixedClock).now = sentinelTestNow.Add(11 * time.Minute)
	if _, err := adapter.DiscoverSchema(context.Background(), sentinelSchemaRequest(config, capability.Digest())); queryconnector.Reason(err) != "sentinel_capability_stale" {
		t.Fatalf("stale err=%v", err)
	}

	adapter, _, config = sentinelTestAdapter(t, 1)
	binding = sentinelTestBinding(config)
	capability, _ = adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	request := sentinelSchemaRequest(config, capability.Digest())
	request.Limits.MaximumPages = 2
	if _, err := adapter.DiscoverSchema(context.Background(), request); queryconnector.Reason(err) != "sentinel_schema_page_limit_exceeded" {
		t.Fatalf("page bound err=%v", err)
	}
}

func TestAdapterValidationAndLifecycleRemainFailClosed(t *testing.T) {
	adapter, _, _ := sentinelTestAdapter(t, 256)
	input, err := os.ReadFile("../../../contracts/query/v1/fixtures/valid/query.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	query, err := queryconnector.DecodeQuery(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := adapter.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "denied" ||
		!slices.Equal(validation.Value().ReasonCodes, []string{"sentinel_validator_unavailable"}) {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	if _, err := adapter.Execute(context.Background(), query, validation); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("execute err=%v", err)
	}
	if _, err := adapter.Poll(context.Background(), queryconnector.PollRequest{}); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("poll err=%v", err)
	}
	if _, err := adapter.NextPage(context.Background(), queryconnector.PageRequest{}); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("page err=%v", err)
	}
	if _, err := adapter.Cancel(context.Background(), queryconnector.CancelRequest{}); queryconnector.Code(err) != queryconnector.Unsupported {
		t.Fatalf("cancel err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Cancel(canceled, queryconnector.CancelRequest{}); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("canceled lifecycle err=%v", err)
	}
}

func sentinelTestAdapter(t *testing.T, pageSize uint32) (*Adapter, *sentinelQualificationClient, Config) {
	t.Helper()
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	config.MaximumSchemaEntriesPerPage = pageSize
	metadata, err := DecodeMetadata(readFixture(t, "metadata.snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	client := &sentinelQualificationClient{metadata: metadata, receipt: CallReceipt{RequestDigest: sentinelTestDigest("1"),
		ResponseDigest: sentinelTestDigest("2"), LeaseDecisionDigest: sentinelTestDigest("3"),
		TransportDigest: config.TransportIdentityDigest}}
	clock := &sentinelFixedClock{now: sentinelTestNow}
	qualifier, err := NewQualifier(config, client, clock)
	if err != nil {
		t.Fatal(err)
	}
	binding := sentinelTestBinding(config)
	qualification, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(config, client, qualification, clock)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, client, config
}

func sentinelSchemaRequest(config Config, capability string) queryconnector.SchemaRequest {
	binding := sentinelTestBinding(config)
	return queryconnector.SchemaRequest{RequestID: "018f1f2e-7a6b-7c8d-8e9f-000000000105", Scope: binding.Scope,
		Authority: binding.Authority, CapabilityDigest: capability, Limits: queryconnector.Limits{MaximumRows: 100,
			MaximumBytes: 100000, MaximumDurationMillis: 5000, MaximumPages: 10, MaximumSlices: 1,
			MaximumCostMillionths: 1000, RequestsPerMinute: 2}}
}
