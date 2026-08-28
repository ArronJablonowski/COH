package splunk

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterPagesFinalizedResultsAndReplaysOpaqueCursor(t *testing.T) {
	adapter, client, pollRequest, pageRequest := prepareSplunkPages(t)
	first, err := adapter.Poll(context.Background(), pollRequest)
	if err != nil || first.Value().Page == nil || len(first.Value().Page.Rows) != 1000 ||
		first.Value().Page.NextPage == nil || first.Value().Completeness.Status != "unknown" {
		t.Fatalf("first=%+v err=%v", first.Value(), err)
	}
	pageRequest.Handle = *first.Value().Page.NextPage
	second, err := adapter.NextPage(context.Background(), pageRequest)
	if err != nil || len(second.Value().Rows) != 500 || second.Value().NextPage != nil ||
		second.Value().Completeness.Status != "complete" || second.Value().Statistics.RowsReturned != 1500 ||
		second.Value().Statistics.PagesReturned != 2 {
		t.Fatalf("second=%+v err=%v", second.Value(), err)
	}
	before := len(client.operations)
	replayed, err := adapter.NextPage(context.Background(), pageRequest)
	if err != nil || replayed.Digest() != second.Digest() || len(client.operations) != before {
		t.Fatalf("replayed=%+v operations=%v err=%v", replayed.Value(), client.operations, err)
	}
}

func TestAdapterNextPageRejectsTheftAndRevokedReplayBeforeVendor(t *testing.T) {
	adapter, client, pollRequest, pageRequest := prepareSplunkPages(t)
	first, err := adapter.Poll(context.Background(), pollRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageRequest.Handle = *first.Value().Page.NextPage
	before := len(client.operations)
	stolen := pageRequest
	stolen.AttemptID = "018f1f2e-7a6b-7c8d-8e9f-000000000999"
	if _, err := adapter.NextPage(context.Background(), stolen); queryconnector.Reason(err) != "splunk_page_handle_mismatch" ||
		len(client.operations) != before {
		t.Fatalf("stolen err=%v operations=%v", err, client.operations)
	}
	if _, err := adapter.NextPage(context.Background(), pageRequest); err != nil {
		t.Fatal(err)
	}
	revocation := splunkparser.RevocationEvidence{SchemaVersion: splunkparser.RevocationVersion,
		ContractVersion: splunkparser.ContractVersion, DecisionDigest: splunkTestDigest("2"),
		RevocationDigest: splunkTestDigest("7"), AuditReservationDigest: splunkTestDigest("3"),
		ReasonCode: "authorization_revoked", ObservedAt: splunkTestNow.Format(splunkTimestampLayout), ExecutionPermitted: false}
	if err := adapter.ApplyRevocation(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	before = len(client.operations)
	if _, err := adapter.NextPage(context.Background(), pageRequest); queryconnector.Reason(err) != "splunk_authority_revoked" ||
		len(client.operations) != before {
		t.Fatalf("revoked replay err=%v operations=%v", err, client.operations)
	}
}

func TestAdapterNextPageCoalescesConcurrentCalls(t *testing.T) {
	adapter, client, pollRequest, pageRequest := prepareSplunkPages(t)
	first, err := adapter.Poll(context.Background(), pollRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageRequest.Handle = *first.Value().Page.NextPage
	release := make(chan struct{})
	client.resultWait = release
	before := len(client.operations)
	const workers = 32
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			page, pageErr := adapter.NextPage(context.Background(), pageRequest)
			if pageErr != nil {
				errors <- pageErr
				return
			}
			results <- page.Digest()
		}()
	}
	close(release)
	wait.Wait()
	close(results)
	close(errors)
	for pageErr := range errors {
		t.Fatal(pageErr)
	}
	want := ""
	for digest := range results {
		if want == "" {
			want = digest
		} else if digest != want {
			t.Fatalf("digest=%s want=%s", digest, want)
		}
	}
	if len(client.operations) != before+1 {
		t.Fatalf("operations=%v", client.operations)
	}
}

func TestAdapterCompletedPollHandlesZeroRowsAndBoundedLimits(t *testing.T) {
	t.Run("zero rows", func(t *testing.T) {
		adapter, client, _, request := prepareSplunkPoll(t)
		client.status = splunkRuntimeStatus("DONE", "1.00000", 10, 0, 0, 50)
		before := len(client.operations)
		poll, err := adapter.Poll(context.Background(), request)
		if err != nil || poll.Value().Outcome != "completed" || poll.Value().Page != nil ||
			poll.Value().Completeness.Status != "complete" || len(client.operations) != before+1 {
			t.Fatalf("poll=%+v operations=%v err=%v", poll.Value(), client.operations, err)
		}
	})
	t.Run("row limit", func(t *testing.T) {
		adapter, client, _, request := prepareSplunkPoll(t)
		client.status = splunkRuntimeStatus("DONE", "1.00000", 120, 101, 101, 75)
		before := len(client.operations)
		poll, err := adapter.Poll(context.Background(), request)
		if err != nil || poll.Value().Outcome != "partial" || !poll.Value().Completeness.Truncated ||
			poll.Value().Completeness.ReasonCodes[0] != "splunk_row_limit_exceeded" ||
			len(client.operations) != before+1 {
			t.Fatalf("poll=%+v operations=%v err=%v", poll.Value(), client.operations, err)
		}
	})
	t.Run("byte limit", func(t *testing.T) {
		adapter, client, _, request := prepareSplunkPoll(t)
		client.status = splunkRuntimeStatus("DONE", "1.00000", 2, 2, 2, 75)
		large := strings.Repeat("x", 60000)
		client.results = ResultEnvelope{SchemaVersion: ResultEnvelopeVersion, ContractVersion: ContractVersion,
			Offset: 0, Count: 2, Total: 2, Fields: []string{"event.time", "source.ip"},
			Results: []map[string]string{{"event.time": large}, {"source.ip": large}}, Messages: []string{},
			ResultDigest: splunkTestDigest("9")}
		poll, err := adapter.Poll(context.Background(), request)
		if err != nil || poll.Value().Outcome != "partial" || poll.Value().Page == nil ||
			len(poll.Value().Page.Rows) != 1 || !poll.Value().Completeness.Truncated ||
			poll.Value().Completeness.ReasonCodes[0] != "splunk_byte_limit_exceeded" {
			t.Fatalf("poll=%+v err=%v", poll.Value(), err)
		}
	})
}

func prepareSplunkPages(t *testing.T) (*Adapter, *qualificationClientStub, queryconnector.PollRequest,
	queryconnector.PageRequest) {
	t.Helper()
	adapter, client, _ := splunkTestAdapter(t, 256)
	adapter.config.HardLimits.MaximumRows = 2000
	client.parser = ParserResult{Commands: []string{"search", "fields", "sort", "head"}}
	client.created = SearchCreateResult{SID: lifecycleTestSID,
		SIDDigest: hashValue("COH-SPLUNK-SID-V1\x00", lifecycleTestSID)}
	capability, schema := prepareValidationAuthority(t, adapter)
	queryValue := splunkValidatedQuery(t, capability.Digest(), schema.Value().SchemaDigest,
		`search resource=security-events | fields event.time,source.ip`).Value()
	queryValue.Limits.MaximumRows = 1500
	queryValue.Limits.MaximumBytes = 500000
	encoded, _ := json.Marshal(queryValue)
	query, err := queryconnector.DecodeQuery(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := adapter.Validate(context.Background(), query)
	if err != nil || validation.Value().Outcome != "accepted" {
		t.Fatalf("validation=%+v err=%v", validation.Value(), err)
	}
	execution, err := adapter.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	pollRequest := queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority}
	client.status = splunkRuntimeStatus("DONE", "1.00000", 1500, 1500, 1500, 80)
	firstRows := make([]map[string]string, 1000)
	for index := range firstRows {
		firstRows[index] = map[string]string{"event.time": "2026-08-27T17:59:00Z", "source.ip": "192.0.2.1"}
	}
	secondRows := make([]map[string]string, 500)
	for index := range secondRows {
		secondRows[index] = map[string]string{"event.time": "2026-08-27T17:59:30Z", "source.ip": "192.0.2.2"}
	}
	client.resultEnvelopes = []ResultEnvelope{
		{SchemaVersion: ResultEnvelopeVersion, ContractVersion: ContractVersion, Offset: 0, Count: 1000, Total: 1500,
			Fields: []string{"event.time", "source.ip"}, Results: firstRows,
			Messages: []string{}, ResultDigest: splunkTestDigest("8")},
		{SchemaVersion: ResultEnvelopeVersion, ContractVersion: ContractVersion, Offset: 1000, Count: 500, Total: 1500,
			Fields: []string{"event.time", "source.ip"}, Results: secondRows,
			Messages: []string{}, ResultDigest: splunkTestDigest("9")},
	}
	adapter.mu.Lock()
	job := adapter.jobs[pollRequest.Handle.HandleID]
	adapter.mu.Unlock()
	pageRequest := queryconnector.PageRequest{QueryID: job.query.QueryID,
		AttemptID: job.execution.Value().AttemptID, Authority: job.query.Authority, Limits: job.query.Limits}
	return adapter, client, pollRequest, pageRequest
}
