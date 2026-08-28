package splunk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterValidationCompilesPreflightsBindsAndReplays(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	capability, schema := prepareValidationAuthority(t, adapter)
	query := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events source.ip="192.0.2.1" | fields event.time,source.ip`)
	before := len(client.operations)
	validation, err := adapter.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" || len(validation.Value().ReasonCodes) != 0 {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	if len(client.operations) != before+1 || client.operations[len(client.operations)-1] != "splunk.parser" {
		t.Fatalf("operations=%v", client.operations)
	}
	replayed, err := adapter.Validate(context.Background(), query)
	if err != nil || replayed.Digest() != validation.Digest() || len(client.operations) != before+1 {
		t.Fatalf("replay=%+v operations=%v err=%v", replayed.Value(), client.operations, err)
	}
	adapter.mu.Lock()
	record := adapter.validations[query.Digest()]
	adapter.mu.Unlock()
	if record.plan.PlanDigest != validation.Value().ProvenanceDigest || validation.Value().CanonicalQueryDigest != query.Digest() ||
		!digestPattern.MatchString(record.plan.QueryDigest) ||
		strings.HasSuffix(record.plan.ParserReceiptDigest, strings.Repeat("0", 64)) ||
		record.plan.ScopeDigest == "" || !strings.Contains(record.plan.CanonicalSPL, "index=security") ||
		strings.Contains(record.plan.CanonicalSPL, "resource=security-events") {
		t.Fatalf("stored plan=%+v", record.plan)
	}
	serialized := strings.ToLower(string(validation.CanonicalBytes()))
	for _, forbidden := range []string{"index=", "src_ip", "192.0.2.1", "authorization", "vendor_body", "sid"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("validation exposes %q: %s", forbidden, serialized)
		}
	}
}

func TestAdapterValidationDeniesLocallyBeforeVendorAndRejectsDrift(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	capability, schema := prepareValidationAuthority(t, adapter)
	before := len(client.operations)
	dangerous := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | collect value`)
	denied, err := adapter.Validate(context.Background(), dangerous)
	if err != nil || denied.Value().Outcome != "denied" ||
		!slicesEqual(denied.Value().ReasonCodes, []string{"spl_command_external_effect"}) || len(client.operations) != before {
		t.Fatalf("denied=%+v operations=%v err=%v", denied.Value(), client.operations, err)
	}
	client.parser = ParserResult{Commands: []string{"search", "collect", "sort", "head"}}
	drift := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | fields event.time,source.ip`)
	denied, err = adapter.Validate(context.Background(), drift)
	if err != nil || denied.Value().Outcome != "denied" ||
		!slicesEqual(denied.Value().ReasonCodes, []string{"splunk_parser_semantic_drift"}) {
		t.Fatalf("drift=%+v err=%v", denied.Value(), err)
	}
}

func TestAdapterValidationHandlesStaleOutageCancellationAndRecovery(t *testing.T) {
	adapter, client, clock := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	capability, schema := prepareValidationAuthority(t, adapter)
	query := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | fields event.time,source.ip`)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Validate(canceled, query); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancel err=%v", err)
	}
	client.err = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
	if _, err := adapter.Validate(context.Background(), query); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("outage err=%v", err)
	}
	client.err = nil
	accepted, err := adapter.Validate(context.Background(), query)
	if err != nil || accepted.Value().Outcome != "accepted" {
		t.Fatalf("recovery=%+v err=%v", accepted.Value(), err)
	}
	second := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events source.ip="198.51.100.1" | fields event.time,source.ip`)
	clock.now = splunkTestNow.Add(11 * time.Minute)
	stale, err := adapter.Validate(context.Background(), second)
	if err != nil || stale.Value().Outcome != "denied" ||
		!slicesEqual(stale.Value().ReasonCodes, []string{"splunk_query_authority_stale"}) {
		t.Fatalf("stale=%+v err=%v", stale.Value(), err)
	}
}

func TestAdapterValidationRejectsQueryIDSubstitutionAndRevocation(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	capability, schema := prepareValidationAuthority(t, adapter)
	original := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | fields event.time,source.ip`)
	accepted, err := adapter.Validate(context.Background(), original)
	if err != nil || accepted.Value().Outcome != "accepted" {
		t.Fatal(err)
	}
	substitutedValue := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events source.ip="203.0.113.2" | fields event.time,source.ip`).Value()
	substitutedValue.QueryID = original.Value().QueryID
	encoded, _ := json.Marshal(substitutedValue)
	substituted, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := adapter.Validate(context.Background(), substituted)
	if err != nil || !slicesEqual(denied.Value().ReasonCodes, []string{"splunk_query_replay_conflict"}) {
		t.Fatalf("substitution=%+v err=%v", denied.Value(), err)
	}
	revocation := splunkparser.RevocationEvidence{SchemaVersion: splunkparser.RevocationVersion,
		ContractVersion: splunkparser.ContractVersion, DecisionDigest: splunkTestDigest("2"),
		RevocationDigest: splunkTestDigest("7"), AuditReservationDigest: splunkTestDigest("3"),
		ReasonCode: "authorization_revoked", ObservedAt: splunkTestNow.Format(splunkTimestampLayout), ExecutionPermitted: false}
	if err := adapter.ApplyRevocation(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	denied, err = adapter.Validate(context.Background(), original)
	if err != nil || !slicesEqual(denied.Value().ReasonCodes, []string{"splunk_authority_revoked"}) {
		t.Fatalf("revoked=%+v err=%v", denied.Value(), err)
	}
	adapter.mu.Lock()
	_, retained := adapter.validations[original.Digest()]
	adapter.mu.Unlock()
	if retained {
		t.Fatal("revoked plan retained")
	}
}

func TestAdapterConcurrentValidationIsDeterministic(t *testing.T) {
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	capability, schema := prepareValidationAuthority(t, adapter)
	query := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | fields event.time,source.ip`)
	const workers = 32
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			validation, err := adapter.Validate(context.Background(), query)
			if err != nil {
				errors <- err
				return
			}
			results <- validation.Digest()
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent validation: %v", err)
	}
	want := ""
	for digest := range results {
		if want == "" {
			want = digest
		} else if digest != want {
			t.Fatalf("validation digest = %s, want %s", digest, want)
		}
	}
	adapter.mu.Lock()
	retained := len(adapter.validations)
	adapter.mu.Unlock()
	if retained != 1 {
		t.Fatalf("retained plans = %d, want 1", retained)
	}
}

func prepareValidationAuthority(t *testing.T, adapter *Adapter) (queryconnector.ValidatedCapability, queryconnector.ValidatedSchemaPage) {
	t.Helper()
	binding := splunkTestBinding("splunk.server_info")
	capability, err := adapter.Probe(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := adapter.DiscoverSchema(context.Background(), splunkSchemaRequest(capability.Digest()))
	if err != nil {
		t.Fatal(err)
	}
	return capability, schema
}

func splunkValidatedQuery(t *testing.T, capability, schema, queryText string) queryconnector.ValidatedQuery {
	t.Helper()
	binding := splunkTestBinding("splunk.parser")
	value := queryconnector.Query{SchemaVersion: queryconnector.QuerySchemaVersion, ContractVersion: queryconnector.ContractVersion,
		QueryID: "018f1f2e-7a6b-7c8d-8e9f-" + queryIDSeed(queryText), Scope: binding.Scope, Authority: binding.Authority,
		CapabilityDigest: capability, SchemaDigest: schema, Language: "spl", NativeText: queryText,
		TimeRange: queryconnector.TimeRange{Start: splunkTestNow.Add(-time.Hour).Format(splunkTimestampLayout), End: splunkTestNow.Format(splunkTimestampLayout)},
		Limits: queryconnector.Limits{MaximumRows: 100, MaximumBytes: 100000, MaximumDurationMillis: 5000,
			MaximumPages: 2, MaximumSlices: 1, MaximumCostMillionths: 1000, RequestsPerMinute: 2},
		RequestedAt: splunkTestNow.Add(-time.Minute).Format(splunkTimestampLayout), Deadline: splunkTestNow.Add(5 * time.Minute).Format(splunkTimestampLayout)}
	encoded, _ := json.Marshal(value)
	validated, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func queryIDSeed(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}
