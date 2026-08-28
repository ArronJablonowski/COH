package splunk

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterExecuteOwnsSIDAndReturnsOpaqueReplay(t *testing.T) {
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	before := len(client.operations)
	execution, err := adapter.Execute(context.Background(), query, validation)
	if err != nil || execution.Value().Outcome != "running" || execution.Value().Handle.Kind != "query_job" {
		t.Fatalf("execution=%+v err=%v", execution.Value(), err)
	}
	replayed, err := adapter.Execute(context.Background(), query, validation)
	if err != nil || replayed.Digest() != execution.Digest() || len(client.operations) != before+1 {
		t.Fatalf("replay=%+v operations=%v err=%v", replayed.Value(), client.operations, err)
	}
	encoded := strings.ToLower(string(execution.CanonicalBytes()))
	for _, forbidden := range []string{strings.ToLower(lifecycleTestSID), "index=", "src_ip", "native_text", "broker-token"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("execution exposes %q: %s", forbidden, encoded)
		}
	}
	adapter.mu.Lock()
	job, retained := adapter.jobs[execution.Value().Handle.HandleID]
	owner := adapter.sidOwners[client.created.SIDDigest]
	adapter.mu.Unlock()
	if !retained || job.sid != lifecycleTestSID || job.sidDigest != client.created.SIDDigest ||
		job.query.NativeText != "" || owner != query.Digest() || job.plan.PlanDigest != validation.Value().ProvenanceDigest {
		t.Fatalf("job=%+v retained=%v owner=%s", job, retained, owner)
	}
}

func TestAdapterExecuteHonorsLowerCompiledHeadAndExpiry(t *testing.T) {
	adapter, _, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip | head 10`)
	if _, err := adapter.Execute(context.Background(), query, validation); err != nil {
		t.Fatalf("lower head err=%v", err)
	}
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	adapter.clock.(*splunkFixedClock).now = splunkTestNow.Add(6 * time.Minute)
	before := len(client.operations)
	if _, err := adapter.Execute(context.Background(), query, validation); queryconnector.Reason(err) != "splunk_execution_validation_mismatch" || len(client.operations) != before {
		t.Fatalf("expired err=%v operations=%v", err, client.operations)
	}
}

func TestAdapterExecuteCoalescesConcurrentDispatch(t *testing.T) {
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	release := make(chan struct{})
	client.createWait = release
	before := len(client.operations)
	const workers = 32
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			execution, err := adapter.Execute(context.Background(), query, validation)
			if err != nil {
				errors <- err
				return
			}
			results <- execution.Digest()
		}()
	}
	close(release)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	want := ""
	for digest := range results {
		if want == "" {
			want = digest
		} else if digest != want {
			t.Fatalf("digest=%s want=%s", digest, want)
		}
	}
	if len(client.operations) != before+1 || client.operations[len(client.operations)-1] != "splunk.search.create" {
		t.Fatalf("operations=%v", client.operations)
	}
}

func TestAdapterExecuteRejectsValidationSubstitutionWithoutDispatch(t *testing.T) {
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	if _, err := adapter.Execute(context.Background(), query, validation); err != nil {
		t.Fatal(err)
	}
	value := validation.Value()
	value.ProvenanceDigest = splunkTestDigest("9")
	encoded, _ := json.Marshal(value)
	substituted, err := queryconnector.DecodeValidation(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	before := len(client.operations)
	if _, err := adapter.Execute(context.Background(), query, substituted); queryconnector.Reason(err) != "splunk_execution_validation_mismatch" || len(client.operations) != before {
		t.Fatalf("err=%v operations=%v", err, client.operations)
	}
}

func TestAdapterExecuteRetainsFailedDispatchForReplaySafety(t *testing.T) {
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	client.err = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
	before := len(client.operations)
	if _, err := adapter.Execute(context.Background(), query, validation); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("first err=%v", err)
	}
	client.err = nil
	if _, err := adapter.Execute(context.Background(), query, validation); queryconnector.Code(err) != queryconnector.Unavailable ||
		len(client.operations) != before+1 {
		t.Fatalf("replay err=%v operations=%v", err, client.operations)
	}
}

func TestAdapterExecuteRejectsCrossQuerySIDCollision(t *testing.T) {
	adapter, client, first, firstValidation := prepareSplunkExecution(t,
		`search resource=security-events source.ip="192.0.2.1" | fields event.time,source.ip`)
	capability, schema := prepareValidationAuthority(t, adapter)
	second := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events source.ip="192.0.2.2" | fields event.time,source.ip`)
	secondValidation, err := adapter.Validate(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(context.Background(), first, firstValidation); err != nil {
		t.Fatal(err)
	}
	before := len(client.operations)
	if _, err := adapter.Execute(context.Background(), second, secondValidation); queryconnector.Reason(err) != "splunk_sid_ownership_conflict" || len(client.operations) != before+1 {
		t.Fatalf("err=%v operations=%v", err, client.operations)
	}
	adapter.mu.Lock()
	jobs := len(adapter.jobs)
	owner := adapter.sidOwners[client.created.SIDDigest]
	adapter.mu.Unlock()
	if jobs != 1 || owner != first.Digest() {
		t.Fatalf("jobs=%d owner=%s", jobs, owner)
	}
}

func prepareSplunkExecution(t *testing.T, text string) (*Adapter, *qualificationClientStub,
	queryconnector.ValidatedQuery, queryconnector.ValidatedValidation) {
	t.Helper()
	adapter, client, _ := splunkTestAdapter(t, 256)
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	client.created = SearchCreateResult{SID: lifecycleTestSID,
		SIDDigest: hashValue("COH-SPLUNK-SID-V1\x00", lifecycleTestSID)}
	capability, schema := prepareValidationAuthority(t, adapter)
	query := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest, text)
	validation, err := adapter.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	return adapter, client, query, validation
}
