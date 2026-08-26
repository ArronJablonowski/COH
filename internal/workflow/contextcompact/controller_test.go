package contextcompact

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	testCompaction = "0199a213-1000-7000-8000-000000000001"
	testRun        = "0199a213-1000-7000-8000-000000000002"
	testTask       = "0199a213-1000-7000-8000-000000000003"
	testOrg        = "0199a213-1000-7000-8000-000000000004"
	testTenant     = "0199a213-1000-7000-8000-000000000005"
	testCase       = "0199a213-1000-7000-8000-000000000006"
	testEvidence1  = "0199a213-1000-7000-8000-000000000007"
	testEvidence2  = "0199a213-1000-7000-8000-000000000008"
	testEvidence3  = "0199a213-1000-7000-8000-000000000009"
	testDigest1    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigest2    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testDigest3    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

var testNow = time.Date(2026, 8, 26, 19, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	value := clock.now
	clock.now = clock.now.Add(time.Nanosecond)
	return value
}

type memoryStore struct {
	mu                     sync.Mutex
	current                State
	beginErrorAfterPersist bool
	saveErrorAfterPersist  bool
}

func (store *memoryStore) Load(_ context.Context, scope domain.CaseRef, id string) (State, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.CompactionID == "" {
		return State{}, false, nil
	}
	if store.current.CompactionID != id || store.current.Case != scope {
		return State{}, false, newError(Denied, "store_scope_mismatch", false, nil)
	}
	return cloneState(store.current), true, nil
}

func (store *memoryStore) Begin(_ context.Context, _ string, next State) (State, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.CompactionID != "" {
		return cloneState(store.current), true, nil
	}
	store.current = cloneState(next)
	if store.beginErrorAfterPersist {
		store.beginErrorAfterPersist = false
		return State{}, false, errors.New("commit response lost")
	}
	return cloneState(next), false, nil
}

func (store *memoryStore) Save(_ context.Context, _ string, prior, next State) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior.Revision != store.current.Revision || prior.ProvenanceDigest != store.current.ProvenanceDigest {
		return State{}, newError(Conflict, "store_revision_conflict", true, nil)
	}
	store.current = cloneState(next)
	if store.saveErrorAfterPersist {
		store.saveErrorAfterPersist = false
		return State{}, errors.New("commit response lost")
	}
	return cloneState(next), nil
}

type writerStub struct {
	calls   int
	request SummaryRequest
	result  domain.ArtifactRef
	err     error
}

type resolverStub struct {
	calls []EvidenceLookup
	err   error
}

func (resolver *resolverStub) Resolve(_ context.Context, lookup EvidenceLookup) error {
	resolver.calls = append(resolver.calls, lookup)
	return resolver.err
}

type blockingWriter struct {
	entered chan struct{}
}

func (writer *blockingWriter) Write(ctx context.Context, _ SummaryRequest) (domain.ArtifactRef, error) {
	close(writer.entered)
	<-ctx.Done()
	return domain.ArtifactRef{}, ctx.Err()
}

type gatedWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (writer *gatedWriter) Write(context.Context, SummaryRequest) (domain.ArtifactRef, error) {
	close(writer.entered)
	<-writer.release
	return validSummary(), nil
}

func (writer *writerStub) Write(ctx context.Context, request SummaryRequest) (domain.ArtifactRef, error) {
	writer.calls++
	writer.request = request
	if writer.err != nil {
		return domain.ArtifactRef{}, writer.err
	}
	select {
	case <-ctx.Done():
		return domain.ArtifactRef{}, ctx.Err()
	default:
		return writer.result, nil
	}
}

func TestCompactPreservesEvidenceSemanticsAndStoresSummaryReferenceSeparately(t *testing.T) {
	store := &memoryStore{}
	writer := &writerStub{result: validSummary()}
	controller := newTestController(t, store, writer)
	request := validRequest()
	result, err := controller.Compact(context.Background(), request)
	if err != nil || result.Status != StatusCompleted || result.Summary != writer.result ||
		result.SummaryTrust != UntrustedEvidence || writer.calls != 1 {
		t.Fatalf("result=%+v state=%+v calls=%d err=%v", result, store.current, writer.calls, err)
	}
	if len(result.Sources) != 3 || result.Sources[1].Result != ResultNegative ||
		result.Sources[2].Completeness != Truncated || result.Sources[0].Precision != PrecisionSecond ||
		result.Sources[1].Order != OrderOverlap || result.Sources[2].Uncertainty != UncertaintyUnknown {
		t.Fatalf("sources not preserved: %+v", result.Sources)
	}
	replacements, replacementErr := result.ReplacementReferences()
	if replacementErr != nil || len(replacements) != 1 || replacements[0] != result.Summary.Digest {
		t.Fatalf("replacements=%v err=%v", replacements, replacementErr)
	}
	if len(writer.request.Sources) != len(request.Intent.Sources) || writer.request.Case != request.Intent.Case {
		t.Fatalf("writer request=%+v", writer.request)
	}
	resolver := controller.resolver.(*resolverStub)
	if len(resolver.calls) != len(request.Intent.Sources) || resolver.calls[0].Case != request.Intent.Case ||
		resolver.calls[0].EvidenceID != request.Intent.Sources[0].EvidenceID ||
		resolver.calls[0].EvidenceDigest != request.Intent.Sources[0].EvidenceDigest {
		t.Fatalf("resolver calls=%+v", resolver.calls)
	}
	canonical, err := CanonicalState(store.current)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"prompt", "instruction", "credential", "tool_authority", "raw_content"} {
		if strings.Contains(string(canonical), forbidden) {
			t.Fatalf("durable state contains forbidden field %q: %s", forbidden, canonical)
		}
	}
}

func TestExactReplayReturnsSameResultAndChangedInputIsDenied(t *testing.T) {
	store := &memoryStore{}
	writer := &writerStub{result: validSummary()}
	controller := newTestController(t, store, writer)
	request := validRequest()
	first, err := controller.Compact(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := controller.Compact(context.Background(), request)
	if err != nil || !replay.Replayed || replay.ProvenanceDigest != first.ProvenanceDigest || writer.calls != 1 {
		t.Fatalf("replay=%+v calls=%d err=%v", replay, writer.calls, err)
	}
	changed := request
	changed.Intent.Sources = cloneSources(request.Intent.Sources)
	changed.Intent.Sources[1].Result = ResultObserved
	if _, err := controller.Compact(context.Background(), changed); ErrorCode(err) != Denied ||
		ErrorReason(err) != "compaction_replay_binding" {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestScopeIdentityOrderingAndReplacementTamperAreDenied(t *testing.T) {
	store := &memoryStore{}
	writer := &writerStub{result: validSummary()}
	controller := newTestController(t, store, writer)
	request := validRequest()
	result, err := controller.Compact(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*Request){
		"case": func(value *Request) {
			value.Intent.Case.CaseID = "0199a213-1000-7000-8000-00000000000a"
		},
		"run": func(value *Request) {
			value.Intent.RunID = "0199a213-1000-7000-8000-00000000000b"
		},
		"task": func(value *Request) {
			value.Intent.TaskID = "0199a213-1000-7000-8000-00000000000c"
		},
		"policy":      func(value *Request) { value.Intent.PolicyDigest = testDigest2 },
		"provider":    func(value *Request) { value.Intent.ProviderRoute = "approved.backup" },
		"idempotency": func(value *Request) { value.IdempotencyKey = "compact-two" },
		"source_order": func(value *Request) {
			value.Intent.Sources[0], value.Intent.Sources[1] = value.Intent.Sources[1], value.Intent.Sources[0]
			value.Intent.Sources[0].Sequence, value.Intent.Sources[1].Sequence = 1, 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			changed.Intent.Sources = cloneSources(request.Intent.Sources)
			mutate(&changed)
			if _, replayErr := controller.Compact(context.Background(), changed); ErrorCode(replayErr) != Denied {
				t.Fatalf("changed replay accepted: %v", replayErr)
			}
		})
	}

	result.Sources[0].EvidenceDigest = testDigest2
	if _, replacementErr := result.ReplacementReferences(); ErrorCode(replacementErr) != Denied {
		t.Fatalf("tampered replacement accepted: %v", replacementErr)
	}
	if writer.calls != 1 {
		t.Fatalf("changed replays invoked writer: %d", writer.calls)
	}
}

func TestAmbiguousCommitsRecoverWithoutRepeatingSummaryWrite(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		store := &memoryStore{beginErrorAfterPersist: true}
		writer := &writerStub{result: validSummary()}
		controller := newTestController(t, store, writer)
		request := validRequest()
		if _, err := controller.Compact(context.Background(), request); ErrorCode(err) != Unavailable {
			t.Fatalf("begin err=%v", err)
		}
		restarted, restartErr := New(store, &resolverStub{}, writer, &testClock{now: request.Intent.Deadline})
		if restartErr != nil {
			t.Fatal(restartErr)
		}
		result, err := restarted.Compact(context.Background(), request)
		if ErrorCode(err) != Conflict || result.Status != StatusUncertain || writer.calls != 0 {
			t.Fatalf("result=%+v calls=%d err=%v", result, writer.calls, err)
		}
	})
	t.Run("completion", func(t *testing.T) {
		store := &memoryStore{saveErrorAfterPersist: true}
		writer := &writerStub{result: validSummary()}
		controller := newTestController(t, store, writer)
		request := validRequest()
		if _, err := controller.Compact(context.Background(), request); ErrorCode(err) != Unavailable {
			t.Fatalf("save err=%v", err)
		}
		result, err := newTestController(t, store, writer).Compact(context.Background(), request)
		if err != nil || !result.Replayed || result.Status != StatusCompleted || writer.calls != 1 {
			t.Fatalf("result=%+v calls=%d err=%v", result, writer.calls, err)
		}
	})
}

func TestConcurrentExactReplayReportsInProgressWithoutCorruptingWriter(t *testing.T) {
	store := &memoryStore{}
	writer := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	controller := newTestController(t, store, writer)
	request := validRequest()
	type outcome struct {
		result Result
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := controller.Compact(context.Background(), request)
		finished <- outcome{result: result, err: err}
	}()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("writer was not entered")
	}
	inProgress, err := controller.Compact(context.Background(), request)
	if ErrorCode(err) != Conflict || ErrorReason(err) != "compaction_in_progress" ||
		inProgress.Status != StatusWriting || !Retryable(err) || store.current.Status != StatusWriting {
		t.Fatalf("result=%+v state=%+v err=%v", inProgress, store.current, err)
	}
	close(writer.release)
	select {
	case first := <-finished:
		if first.err != nil || first.result.Status != StatusCompleted || store.current.Status != StatusCompleted {
			t.Fatalf("result=%+v state=%+v err=%v", first.result, store.current, first.err)
		}
	case <-time.After(time.Second):
		t.Fatal("first compaction did not finish")
	}
}

func TestInvalidInputsWriterFailuresCancellationAndTamperFailClosed(t *testing.T) {
	for name, mutate := range map[string]func(*Request){
		"missing_sources":  func(value *Request) { value.Intent.Sources = nil },
		"wrong_sequence":   func(value *Request) { value.Intent.Sources[1].Sequence = 7 },
		"duplicate_source": func(value *Request) { value.Intent.Sources[1].EvidenceID = testEvidence1 },
		"trusted_content":  func(value *Request) { value.Intent.Sources[0].Trust = "trusted_instruction" },
		"bad_time":         func(value *Request) { value.Intent.Sources[0].SourceTime = "yesterday" },
	} {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(&request)
			store := &memoryStore{}
			writer := &writerStub{result: validSummary()}
			if _, err := newTestController(t, store, writer).Compact(context.Background(), request); ErrorCode(err) != InvalidInput || writer.calls != 0 {
				t.Fatalf("calls=%d err=%v", writer.calls, err)
			}
		})
	}

	store := &memoryStore{}
	writer := &writerStub{result: validSummary()}
	resolver := &resolverStub{err: newError(Denied, "compaction_evidence_unresolvable", false, nil)}
	controller, controllerErr := New(store, resolver, writer, &testClock{now: testNow})
	if controllerErr != nil {
		t.Fatal(controllerErr)
	}
	if _, err := controller.Compact(context.Background(), validRequest()); ErrorCode(err) != Denied ||
		ErrorReason(err) != "compaction_evidence_unresolvable" || len(resolver.calls) != 1 ||
		writer.calls != 0 || store.current.CompactionID != "" {
		t.Fatalf("resolver calls=%d writer=%d state=%+v err=%v", len(resolver.calls), writer.calls, store.current, err)
	}

	store = &memoryStore{}
	writer = &writerStub{result: domain.ArtifactRef{Digest: "bad"}}
	result, err := newTestController(t, store, writer).Compact(context.Background(), validRequest())
	if ErrorCode(err) != Denied || result.Status != StatusUncertain || store.current.Status != StatusUncertain {
		t.Fatalf("invalid summary result=%+v state=%+v err=%v", result, store.current, err)
	}
	if _, replacementErr := result.ReplacementReferences(); ErrorCode(replacementErr) != Denied {
		t.Fatalf("uncertain result became replaceable: %v", replacementErr)
	}

	store = &memoryStore{}
	writer = &writerStub{err: errors.New("provider unavailable")}
	result, err = newTestController(t, store, writer).Compact(context.Background(), validRequest())
	if ErrorCode(err) != Unavailable || result.Status != StatusUncertain || store.current.ReasonCode != "summary_dependency_unavailable" {
		t.Fatalf("writer result=%+v state=%+v err=%v", result, store.current, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store = &memoryStore{}
	writer = &writerStub{result: validSummary()}
	if _, err := newTestController(t, store, writer).Compact(ctx, validRequest()); ErrorCode(err) != Canceled || store.current.CompactionID != "" {
		t.Fatalf("cancel state=%+v err=%v", store.current, err)
	}

	request := validRequest()
	request.Intent.Deadline = testNow
	store = &memoryStore{}
	writer = &writerStub{result: validSummary()}
	if _, err := newTestController(t, store, writer).Compact(context.Background(), request); ErrorCode(err) != Timeout || store.current.CompactionID != "" {
		t.Fatalf("deadline state=%+v err=%v", store.current, err)
	}

	store = &memoryStore{}
	writer = &writerStub{result: validSummary()}
	controller = newTestController(t, store, writer)
	if _, err := controller.Compact(context.Background(), validRequest()); err != nil {
		t.Fatal(err)
	}
	store.current.Sources[0].Completeness = Unknown
	if _, err := controller.Compact(context.Background(), validRequest()); ErrorCode(err) != Denied {
		t.Fatalf("tamper err=%v", err)
	}

	store = &memoryStore{}
	writer = &writerStub{result: validSummary()}
	controller = newTestController(t, store, writer)
	if _, err := controller.Compact(context.Background(), validRequest()); err != nil {
		t.Fatal(err)
	}
	store.current.Revision = 1
	forged, digestErr := provenanceDigest(store.current.PreviousProvenanceDigest,
		store.current.ReasonCode, store.current)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	store.current.ProvenanceDigest = forged
	if _, err := controller.Compact(context.Background(), validRequest()); ErrorCode(err) != Denied ||
		ErrorReason(err) != "compaction_state_invalid" {
		t.Fatalf("invalid transition accepted: %v", err)
	}
}

func TestCancellationAndTimeoutDuringSummaryWriteBecomeDurableUncertainty(t *testing.T) {
	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
		"canceled": func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		},
		"timeout": func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 20*time.Millisecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &memoryStore{}
			writer := &blockingWriter{entered: make(chan struct{})}
			controller := newTestController(t, store, writer)
			ctx, cancel := makeContext()
			defer cancel()
			type outcome struct {
				result Result
				err    error
			}
			finished := make(chan outcome, 1)
			go func() {
				result, err := controller.Compact(ctx, validRequest())
				finished <- outcome{result: result, err: err}
			}()
			select {
			case <-writer.entered:
			case <-time.After(time.Second):
				t.Fatal("writer was not entered")
			}
			if name == "canceled" {
				cancel()
			}
			select {
			case got := <-finished:
				wantCode, wantReason := Canceled, "summary_canceled"
				if name == "timeout" {
					wantCode, wantReason = Timeout, "summary_timeout"
				}
				if ErrorCode(got.err) != wantCode || got.result.Status != StatusUncertain ||
					store.current.Status != StatusUncertain || store.current.ReasonCode != wantReason {
					t.Fatalf("result=%+v state=%+v err=%v", got.result, store.current, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("compaction did not terminate")
			}
		})
	}
}

func validRequest() Request {
	sources := []Source{
		{Sequence: 1, EvidenceID: testEvidence1, EvidenceDigest: testDigest1, Trust: UntrustedEvidence,
			SourceTime: "2026-08-26T12:00:00-07:00", NormalizedTime: "2026-08-26T19:00:00.000000000Z",
			OriginalTimezone: "America/Denver", Precision: PrecisionSecond, ClockUncertaintyNanoseconds: 1_000_000_000,
			Order: OrderStrict, Result: ResultObserved, Completeness: Complete, Uncertainty: UncertaintyClock},
		{Sequence: 2, EvidenceID: testEvidence2, EvidenceDigest: testDigest2, Trust: UntrustedEvidence,
			SourceTime: "2026-08-26T19:00:01Z", NormalizedTime: "2026-08-26T19:00:01.000000000Z",
			OriginalTimezone: "UTC", Precision: PrecisionMillisecond, ClockUncertaintyNanoseconds: 500_000_000,
			Order: OrderOverlap, Result: ResultNegative, Completeness: Complete, Uncertainty: UncertaintyBounded},
		{Sequence: 3, EvidenceID: testEvidence3, EvidenceDigest: testDigest3, Trust: UntrustedEvidence,
			SourceTime: "2026-08-26T19:01:00Z", NormalizedTime: "2026-08-26T19:01:00.000000000Z",
			OriginalTimezone: "UTC", Precision: PrecisionMinute, ClockUncertaintyNanoseconds: 0,
			Order: OrderUnknown, Result: ResultGap, Completeness: Truncated, Uncertainty: UncertaintyUnknown},
	}
	return Request{IdempotencyKey: "compact-one", Intent: Intent{SchemaVersion: SchemaVersion,
		ContractVersion: ContractVersion, CompactionID: testCompaction, RunID: testRun, TaskID: testTask,
		Case: testScope(), PolicyDigest: testDigest1, ProviderRoute: "ollama.local", Sources: sources,
		CreatedAt: testNow.Add(-time.Minute), Deadline: testNow.Add(time.Hour)}}
}

func validSummary() domain.ArtifactRef {
	return domain.ArtifactRef{Digest: testDigest3, MediaType: "application/json", Classification: "internal", Length: 512}
}

func testScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
}

func newTestController(t *testing.T, store Store, writer SummaryWriter) *Controller {
	t.Helper()
	controller, err := New(store, &resolverStub{}, writer, &testClock{now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
