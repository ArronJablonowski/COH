package splunk

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterCancelConfirmsTerminalStateAndReplays(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	client.status = splunkRuntimeStatus("USER_CANCEL", "0.50000", 20, 10, 1, 100)
	cancellation, err := adapter.Cancel(context.Background(), request)
	if err != nil || cancellation.Value().Outcome != "confirmed" || cancellation.Value().ConfirmedAt == nil {
		t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
	}
	if len(client.operations) < 2 || client.operations[len(client.operations)-2] != "splunk.search.cancel" ||
		client.operations[len(client.operations)-1] != "splunk.search.status" {
		t.Fatalf("operations=%v", client.operations)
	}
	before := len(client.operations)
	replayed, err := adapter.Cancel(context.Background(), request)
	if err != nil || replayed.Digest() != cancellation.Digest() || len(client.operations) != before {
		t.Fatalf("replayed=%+v operations=%v err=%v", replayed.Value(), client.operations, err)
	}
	adapter.mu.Lock()
	_, retained := adapter.jobs[request.Handle.HandleID]
	adapter.mu.Unlock()
	if retained {
		t.Fatal("canceled job retained")
	}
}

func TestAdapterCancelReturnsUncertainAndBlocksRelease(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*qualificationClientStub)
	}{
		{"cancel outage", func(client *qualificationClientStub) {
			client.cancelErr = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
		}},
		{"cancel not acknowledged", func(client *qualificationClientStub) { client.canceled.Acknowledged = false }},
		{"status outage", func(client *qualificationClientStub) {
			client.statusErr = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, client, request := prepareSplunkCancellation(t)
			client.status = splunkRuntimeStatus("USER_CANCEL", "0.50000", 20, 10, 1, 100)
			test.mutate(client)
			cancellation, err := adapter.Cancel(context.Background(), request)
			if err != nil || cancellation.Value().Outcome != "uncertain" || cancellation.Value().ConfirmedAt != nil {
				t.Fatalf("cancellation=%+v err=%v", cancellation.Value(), err)
			}
			pollRequest := queryconnector.PollRequest{QueryID: request.QueryID, AttemptID: request.AttemptID,
				Handle: request.Handle, Authority: request.Authority}
			before := len(client.operations)
			if _, err := adapter.Poll(context.Background(), pollRequest); queryconnector.Reason(err) != "splunk_job_unavailable" ||
				len(client.operations) != before {
				t.Fatalf("poll err=%v operations=%v", err, client.operations)
			}
		})
	}
}

func TestAdapterCancelRejectsMismatchAndHandlesUnknownOrTerminalJob(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	before := len(client.operations)
	stolen := request
	stolen.AttemptID = "018f1f2e-7a6b-7c8d-8e9f-000000000999"
	if _, err := adapter.Cancel(context.Background(), stolen); queryconnector.Reason(err) != "splunk_job_mismatch" ||
		len(client.operations) != before {
		t.Fatalf("stolen err=%v operations=%v", err, client.operations)
	}
	unknown := request
	unknown.Handle.HandleID = "018f1f2e-7a6b-7c8d-8e9f-000000000998"
	result, err := adapter.Cancel(context.Background(), unknown)
	if err != nil || result.Value().Outcome != "uncertain" || len(client.operations) != before {
		t.Fatalf("unknown=%+v operations=%v err=%v", result.Value(), client.operations, err)
	}

	adapter, client, request = prepareSplunkCancellation(t)
	adapter.mu.Lock()
	job := adapter.jobs[request.Handle.HandleID]
	status := splunkRuntimeStatus("DONE", "1.00000", 20, 10, 1, 100)
	job.lastStatus = &status
	adapter.jobs[request.Handle.HandleID] = job
	adapter.mu.Unlock()
	before = len(client.operations)
	result, err = adapter.Cancel(context.Background(), request)
	if err != nil || result.Value().Outcome != "confirmed" || len(client.operations) != before {
		t.Fatalf("terminal=%+v operations=%v err=%v", result.Value(), client.operations, err)
	}
}

func TestAdapterCancelCoalescesConcurrentCalls(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	client.status = splunkRuntimeStatus("USER_CANCEL", "0.50000", 20, 10, 1, 100)
	release := make(chan struct{})
	client.cancelWait = release
	before := len(client.operations)
	const workers = 32
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := adapter.Cancel(context.Background(), request)
			if err != nil {
				errors <- err
				return
			}
			results <- result.Digest()
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
	if len(client.operations) != before+2 {
		t.Fatalf("operations=%v", client.operations)
	}
}

func TestAdapterCancelBoundsNonterminalConfirmation(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	client.status = splunkRuntimeStatus("RUNNING", "0.50000", 20, 10, 1, 100)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	result, err := adapter.Cancel(ctx, request)
	if err != nil || result.Value().Outcome != "uncertain" || result.Value().ConfirmedAt != nil {
		t.Fatalf("result=%+v err=%v", result.Value(), err)
	}
	if client.operations[len(client.operations)-2] != "splunk.search.cancel" ||
		client.operations[len(client.operations)-1] != "splunk.search.status" {
		t.Fatalf("operations=%v", client.operations)
	}
}

func TestAdapterCancelValidatesTimestampAndContext(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	request.RequestedAt = splunkTestNow.Add(time.Second).Format(splunkTimestampLayout)
	before := len(client.operations)
	if _, err := adapter.Cancel(context.Background(), request); queryconnector.Reason(err) != "splunk_cancellation_request_invalid" ||
		len(client.operations) != before {
		t.Fatalf("future err=%v operations=%v", err, client.operations)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Cancel(canceled, request); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("context err=%v", err)
	}
}

func TestAdapterRevocationAttemptsCancellationOnceAndBlocksRelease(t *testing.T) {
	adapter, client, request := prepareSplunkCancellation(t)
	client.status = splunkRuntimeStatus("USER_CANCEL", "0.50000", 20, 10, 1, 100)
	revocation := splunkparser.RevocationEvidence{SchemaVersion: splunkparser.RevocationVersion,
		ContractVersion: splunkparser.ContractVersion, DecisionDigest: splunkTestDigest("2"),
		RevocationDigest: splunkTestDigest("7"), AuditReservationDigest: splunkTestDigest("3"),
		ReasonCode: "authorization_revoked", ObservedAt: splunkTestNow.Format(splunkTimestampLayout), ExecutionPermitted: false}
	before := len(client.operations)
	if err := adapter.ApplyRevocation(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	if len(client.operations) != before+2 || client.operations[len(client.operations)-2] != "splunk.search.cancel" ||
		client.operations[len(client.operations)-1] != "splunk.search.status" {
		t.Fatalf("operations=%v", client.operations)
	}
	adapter.mu.Lock()
	automatic := adapter.automaticCancellations[request.Handle.HandleID]
	_, retained := adapter.jobs[request.Handle.HandleID]
	adapter.mu.Unlock()
	if automatic.Value().Outcome != "confirmed" || !retained {
		t.Fatalf("automatic=%+v retained=%t", automatic.Value(), retained)
	}
	pollRequest := queryconnector.PollRequest{QueryID: request.QueryID, AttemptID: request.AttemptID,
		Handle: request.Handle, Authority: request.Authority}
	before = len(client.operations)
	if _, err := adapter.Poll(context.Background(), pollRequest); queryconnector.Reason(err) != "splunk_authority_revoked" ||
		len(client.operations) != before {
		t.Fatalf("poll err=%v operations=%v", err, client.operations)
	}
	if err := adapter.ApplyRevocation(context.Background(), revocation); err != nil || len(client.operations) != before {
		t.Fatalf("replay err=%v operations=%v", err, client.operations)
	}
}

func prepareSplunkCancellation(t *testing.T) (*Adapter, *qualificationClientStub, queryconnector.CancelRequest) {
	t.Helper()
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	execution, err := adapter.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	client.canceled = SearchCancelResult{Acknowledged: true}
	value := execution.Value()
	return adapter, client, queryconnector.CancelRequest{QueryID: query.Value().QueryID, AttemptID: value.AttemptID,
		Handle: value.Handle, Authority: query.Value().Authority, RequestedAt: splunkTestNow.Format(splunkTimestampLayout)}
}
