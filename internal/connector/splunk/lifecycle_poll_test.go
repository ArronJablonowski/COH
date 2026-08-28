package splunk

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/splunkparser"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestAdapterPollEnforcesCadenceAndMonotonicProgress(t *testing.T) {
	adapter, client, clock, request := prepareSplunkPoll(t)
	client.statuses = []JobStatus{
		splunkRuntimeStatus("RUNNING", "0.50000", 20, 10, 1, 100),
		splunkRuntimeStatus("FINALIZING", "0.90000", 40, 20, 2, 125),
		splunkRuntimeStatus("DONE", "1.00000", 40, 20, 2, 125),
	}
	before := len(client.operations)
	first, err := adapter.Poll(context.Background(), request)
	if err != nil || first.Value().Outcome != "running" ||
		first.Value().Completeness.ReasonCodes[0] != "splunk_job_running" {
		t.Fatalf("first=%+v err=%v", first.Value(), err)
	}
	cached, err := adapter.Poll(context.Background(), request)
	if err != nil || cached.Digest() != first.Digest() || len(client.operations) != before+1 {
		t.Fatalf("cached=%+v operations=%v err=%v", cached.Value(), client.operations, err)
	}
	clock.now = clock.now.Add(minimumSplunkPollInterval)
	second, err := adapter.Poll(context.Background(), request)
	if err != nil || second.Digest() == first.Digest() || second.Value().Statistics.RowsScanned != 40 {
		t.Fatalf("second=%+v err=%v", second.Value(), err)
	}
	clock.now = clock.now.Add(minimumSplunkPollInterval)
	ready, err := adapter.Poll(context.Background(), request)
	if err != nil || ready.Value().Outcome != "running" ||
		ready.Value().Completeness.ReasonCodes[0] != "splunk_results_pending" {
		t.Fatalf("ready=%+v err=%v", ready.Value(), err)
	}
}

func TestAdapterPollReportsTerminalFailureAndCancellation(t *testing.T) {
	tests := []struct {
		state, outcome, reason string
	}{
		{"FAILED", "failed", "splunk_job_failed"},
		{"BAD_INPUT_CANCEL", "canceled", "splunk_job_bad_input_canceled"},
		{"INTERNAL_CANCEL", "canceled", "splunk_job_internal_canceled"},
		{"USER_CANCEL", "canceled", "splunk_job_user_canceled"},
		{"QUIT", "canceled", "splunk_job_quit"},
	}
	for _, test := range tests {
		t.Run(test.state, func(t *testing.T) {
			adapter, client, _, request := prepareSplunkPoll(t)
			status := splunkRuntimeStatus(test.state, "0.75000", 30, 15, 1, 110)
			if test.state == "FAILED" {
				status.Failed = true
			}
			client.status = status
			poll, err := adapter.Poll(context.Background(), request)
			if err != nil || poll.Value().Outcome != test.outcome || poll.Value().Completeness.Status != "partial" ||
				poll.Value().Completeness.ReasonCodes[0] != test.reason || !poll.Value().Completeness.VendorConfirmed {
				t.Fatalf("poll=%+v err=%v", poll.Value(), err)
			}
		})
	}
}

func TestAdapterPollRejectsMismatchDeadlineAndRevocationBeforeVendor(t *testing.T) {
	adapter, client, clock, request := prepareSplunkPoll(t)
	client.status = splunkRuntimeStatus("RUNNING", "0.50000", 20, 10, 1, 100)
	before := len(client.operations)
	stolen := request
	stolen.AttemptID = "018f1f2e-7a6b-7c8d-8e9f-000000000999"
	if _, err := adapter.Poll(context.Background(), stolen); queryconnector.Reason(err) != "splunk_job_mismatch" ||
		len(client.operations) != before {
		t.Fatalf("stolen err=%v operations=%v", err, client.operations)
	}
	clock.now = splunkTestNow.Add(6 * time.Minute)
	if _, err := adapter.Poll(context.Background(), request); queryconnector.Reason(err) != "splunk_job_deadline_exceeded" ||
		len(client.operations) != before {
		t.Fatalf("deadline err=%v operations=%v", err, client.operations)
	}

	adapter, client, _, request = prepareSplunkPoll(t)
	revocation := splunkparser.RevocationEvidence{SchemaVersion: splunkparser.RevocationVersion,
		ContractVersion: splunkparser.ContractVersion, DecisionDigest: splunkTestDigest("2"),
		RevocationDigest: splunkTestDigest("7"), AuditReservationDigest: splunkTestDigest("3"),
		ReasonCode: "authorization_revoked", ObservedAt: splunkTestNow.Format(splunkTimestampLayout), ExecutionPermitted: false}
	if err := adapter.ApplyRevocation(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	before = len(client.operations)
	if _, err := adapter.Poll(context.Background(), request); queryconnector.Reason(err) != "splunk_authority_revoked" ||
		len(client.operations) != before {
		t.Fatalf("revoked err=%v operations=%v", err, client.operations)
	}
}

func TestAdapterPollRejectsRegressionAndRecoversFromOutage(t *testing.T) {
	adapter, client, clock, request := prepareSplunkPoll(t)
	client.statuses = []JobStatus{
		splunkRuntimeStatus("RUNNING", "0.60000", 30, 15, 1, 100),
		splunkRuntimeStatus("PARSING", "0.50000", 20, 10, 1, 90),
		splunkRuntimeStatus("RUNNING", "0.70000", 40, 20, 2, 120),
	}
	if _, err := adapter.Poll(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(minimumSplunkPollInterval)
	if _, err := adapter.Poll(context.Background(), request); queryconnector.Reason(err) != "splunk_search_state_regression" {
		t.Fatalf("regression err=%v", err)
	}
	client.err = queryconnector.NewError(queryconnector.Unavailable, "splunk_vendor_unavailable", nil)
	if _, err := adapter.Poll(context.Background(), request); queryconnector.Code(err) != queryconnector.Unavailable {
		t.Fatalf("outage err=%v", err)
	}
	client.err = nil
	recovered, err := adapter.Poll(context.Background(), request)
	if err != nil || recovered.Value().Statistics.RowsScanned != 40 {
		t.Fatalf("recovered=%+v err=%v", recovered.Value(), err)
	}
}

func TestAdapterPollCoalescesConcurrentStatusCalls(t *testing.T) {
	adapter, client, _, request := prepareSplunkPoll(t)
	client.status = splunkRuntimeStatus("RUNNING", "0.50000", 20, 10, 1, 100)
	release := make(chan struct{})
	client.statusWait = release
	before := len(client.operations)
	const workers = 32
	results := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			poll, err := adapter.Poll(context.Background(), request)
			if err != nil {
				errors <- err
				return
			}
			results <- poll.Digest()
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
	if len(client.operations) != before+1 {
		t.Fatalf("operations=%v", client.operations)
	}
}

func prepareSplunkPoll(t *testing.T) (*Adapter, *qualificationClientStub, *splunkFixedClock,
	queryconnector.PollRequest) {
	t.Helper()
	adapter, client, query, validation := prepareSplunkExecution(t,
		`search resource=security-events | fields event.time,source.ip`)
	execution, err := adapter.Execute(context.Background(), query, validation)
	if err != nil {
		t.Fatal(err)
	}
	clock := adapter.clock.(*splunkFixedClock)
	return adapter, client, clock, queryconnector.PollRequest{QueryID: query.Value().QueryID,
		AttemptID: execution.Value().AttemptID, Handle: execution.Value().Handle, Authority: query.Value().Authority}
}

func splunkRuntimeStatus(state, progress string, scan, events, results, duration uint64) JobStatus {
	done := terminalSplunkState(state)
	return JobStatus{SchemaVersion: JobStatusVersion, ContractVersion: ContractVersion, State: state,
		DoneProgress: progress, ScanCount: scan, EventCount: events, ResultCount: results,
		DurationMillis: duration, Done: done}
}
