package recoverycontrol

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type gatedProvider struct {
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (provider *gatedProvider) InvokeProvider(_ context.Context, request AttemptRequest) (AttemptReceipt, error) {
	provider.mu.Lock()
	provider.calls++
	provider.mu.Unlock()
	close(provider.entered)
	<-provider.release
	return AttemptReceipt{AttemptID: request.AttemptID, Route: request.Route,
		CapabilityDigest: request.CapabilityDigest, Outcome: "succeeded", Artifact: validArtifactRef(),
		EvidenceDigest: testDigest3}, nil
}

func TestRecoveryResumesSafeWorkExactlyAndPreservesTerminalOrUncertainState(t *testing.T) {
	t.Run("safe resume and replay", func(t *testing.T) {
		store := &memoryStore{}
		work := &workStub{inspect: validWorkSnapshot(WorkRunning, NoSideEffect),
			resume: validWorkSnapshot(WorkWaiting, NoSideEffect)}
		controller := newController(t, store, work, nil, nil, nil)
		result, err := controller.Recover(context.Background(), validRecoverRequest())
		if err != nil || result.Status != Completed || result.Work.Status != WorkWaiting || work.calls != 1 {
			t.Fatalf("result=%+v calls=%d err=%v", result, work.calls, err)
		}
		replay, err := controller.Recover(context.Background(), validRecoverRequest())
		if err != nil || !replay.Replayed || replay.ProvenanceDigest != result.ProvenanceDigest || work.calls != 1 {
			t.Fatalf("replay=%+v calls=%d err=%v", replay, work.calls, err)
		}
	})

	for name, snapshot := range map[string]WorkSnapshot{
		"failed":        validWorkSnapshot(WorkFailed, NoSideEffect),
		"denied":        validWorkSnapshot(WorkDenied, NoSideEffect),
		"canceled":      validWorkSnapshot(WorkCanceled, NoSideEffect),
		"timeout":       validWorkSnapshot(WorkTimeout, NoSideEffect),
		"uncertain":     validWorkSnapshot(WorkUncertain, IndeterminateSideEffect),
		"indeterminate": validWorkSnapshot(WorkRunning, IndeterminateSideEffect),
	} {
		t.Run(name, func(t *testing.T) {
			store := &memoryStore{}
			work := &workStub{inspect: snapshot, resume: validWorkSnapshot(WorkSucceeded, NoSideEffect)}
			controller := newController(t, store, work, nil, nil, nil)
			result, err := controller.Recover(context.Background(), validRecoverRequest())
			if work.calls != 0 || result.Status != controlStatus(snapshot.Status) && result.Status != Uncertain {
				t.Fatalf("result=%+v calls=%d err=%v", result, work.calls, err)
			}
			if result.Status == Uncertain && ErrorCode(err) != Conflict || result.Status != Uncertain && err != nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestRecoveryChangedReplayAndConfirmedReceiptMutationAreDenied(t *testing.T) {
	store := &memoryStore{}
	observed := validWorkSnapshot(WorkRunning, ConfirmedSideEffect)
	resumed := validWorkSnapshot(WorkWaiting, ConfirmedSideEffect)
	resumed.ReceiptDigest = testDigest1
	work := &workStub{inspect: observed, resume: resumed}
	controller := newController(t, store, work, nil, nil, nil)
	if _, err := controller.Recover(context.Background(), validRecoverRequest()); ErrorCode(err) != DeniedCode {
		t.Fatalf("receipt mutation accepted: %v", err)
	}

	store = &memoryStore{}
	work = &workStub{inspect: validWorkSnapshot(WorkRunning, NoSideEffect),
		resume: validWorkSnapshot(WorkWaiting, NoSideEffect)}
	controller = newController(t, store, work, nil, nil, nil)
	if _, err := controller.Recover(context.Background(), validRecoverRequest()); err != nil {
		t.Fatal(err)
	}
	changed := validRecoverRequest()
	changed.PolicyDigest = testDigest2
	if _, err := controller.Recover(context.Background(), changed); ErrorCode(err) != DeniedCode {
		t.Fatalf("changed replay accepted: %v", err)
	}
}

func TestRecoveryRejectsChangedIntentOrLostConfirmedSideEffect(t *testing.T) {
	for name, mutate := range map[string]func(*WorkSnapshot){
		"intent": func(value *WorkSnapshot) { value.IntentDigest = testDigest2 },
		"side_effect": func(value *WorkSnapshot) {
			value.SideEffect = NoSideEffect
			value.ReceiptDigest = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			observed := validWorkSnapshot(WorkRunning, ConfirmedSideEffect)
			resumed := validWorkSnapshot(WorkWaiting, ConfirmedSideEffect)
			mutate(&resumed)
			work := &workStub{inspect: observed, resume: resumed}
			controller := newController(t, &memoryStore{}, work, nil, nil, nil)
			if _, err := controller.Recover(context.Background(), validRecoverRequest()); ErrorCode(err) != DeniedCode {
				t.Fatalf("changed recovery result accepted: %+v err=%v", resumed, err)
			}
		})
	}
}

func TestLostRecoverySaveResponseReplaysWithoutResumingTwice(t *testing.T) {
	store := &memoryStore{saveErrorAfterPersist: true}
	work := &workStub{inspect: validWorkSnapshot(WorkRunning, NoSideEffect),
		resume: validWorkSnapshot(WorkWaiting, NoSideEffect)}
	controller := newController(t, store, work, nil, nil, nil)
	if _, err := controller.Recover(context.Background(), validRecoverRequest()); ErrorCode(err) != Unavailable {
		t.Fatalf("lost response err=%v", err)
	}
	result, err := controller.Recover(context.Background(), validRecoverRequest())
	if err != nil || result.Status != Completed || !result.Replayed || work.calls != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, work.calls, err)
	}
}

func TestRecoveryPastDeadlineBecomesUncertainWithoutResume(t *testing.T) {
	request := validRecoverRequest()
	work := &workStub{inspect: validWorkSnapshot(WorkRunning, NoSideEffect),
		resume: validWorkSnapshot(WorkWaiting, NoSideEffect)}
	store := &memoryStore{}
	cancel := validCancelStub(store)
	controller, err := New(store, work, cancel, cancel, &routeStub{approved: validApprovedRoute(t)},
		&providerStub{}, &testClock{now: request.Deadline})
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Recover(context.Background(), request)
	if ErrorCode(err) != Conflict || ErrorReason(err) != "recovery_deadline_elapsed" ||
		result.Status != Uncertain || work.calls != 0 || store.current.Status != Uncertain {
		t.Fatalf("result=%+v calls=%d state=%+v err=%v", result, work.calls, store.current, err)
	}
}

func TestCancellationIntentIsDurableBeforeOrderedChildAndToolPropagation(t *testing.T) {
	store := &memoryStore{}
	cancel := validCancelStub(store)
	controller := newController(t, store, nil, cancel, nil, nil)
	result, err := controller.Cancel(context.Background(), validCancelRequest())
	if err != nil || result.Status != Completed || len(result.Acknowledgments) != 2 || len(cancel.calls) != 2 ||
		cancel.calls[0].Target.Kind != ChildTask || cancel.calls[1].Target.Kind != ToolJob {
		t.Fatalf("result=%+v calls=%+v err=%v", result, cancel.calls, err)
	}
	request := validCancelRequest()
	for index, command := range cancel.calls {
		target := request.Targets[index]
		if command.IdempotencyKey != request.IdempotencyKey+":target:"+target.TargetID ||
			command.Case != request.Case || command.RunID != request.RunID || command.RootTaskID != request.TaskID ||
			command.Target != target || command.ReasonDigest != request.ReasonDigest ||
			!command.Deadline.Equal(request.Deadline) {
			t.Fatalf("command %d lost cancellation bindings: %+v", index, command)
		}
	}
	replay, err := controller.Cancel(context.Background(), validCancelRequest())
	if err != nil || !replay.Replayed || len(cancel.calls) != 2 {
		t.Fatalf("replay=%+v calls=%d err=%v", replay, len(cancel.calls), err)
	}
}

func TestCancellationPastDeadlinePersistsUncertaintyForEveryUncontactedTarget(t *testing.T) {
	request := validCancelRequest()
	store := &memoryStore{}
	cancel := validCancelStub(store)
	controller, err := New(store, &workStub{}, cancel, cancel, &routeStub{approved: validApprovedRoute(t)},
		&providerStub{}, &testClock{now: request.Deadline})
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Cancel(context.Background(), request)
	if ErrorCode(err) != Conflict || result.Status != Uncertain || len(cancel.calls) != 0 ||
		len(result.Acknowledgments) != len(request.Targets) {
		t.Fatalf("result=%+v calls=%d err=%v", result, len(cancel.calls), err)
	}
	for _, ack := range result.Acknowledgments {
		if ack.Outcome != AckUncertain || ack.EvidenceDigest == "" || ack.ProvenanceDigest == "" {
			t.Fatalf("deadline acknowledgment=%+v", ack)
		}
	}
}

func TestCancellationAmbiguousAcknowledgmentBecomesDurableUncertaintyAndContinues(t *testing.T) {
	store := &memoryStore{}
	cancel := validCancelStub(store)
	cancel.errs[testChild] = errors.New("connection lost after dispatch")
	controller := newController(t, store, nil, cancel, nil, nil)
	result, err := controller.Cancel(context.Background(), validCancelRequest())
	if ErrorCode(err) != Conflict || result.Status != Uncertain || len(result.Acknowledgments) != 2 ||
		result.Acknowledgments[0].Outcome != AckUncertain || result.Acknowledgments[1].Outcome != AckAlreadyTerminal ||
		len(cancel.calls) != 2 {
		t.Fatalf("result=%+v calls=%d err=%v", result, len(cancel.calls), err)
	}
}

func TestCancellationLostAcknowledgmentSaveResponseResumesAtExactNextTarget(t *testing.T) {
	store := &memoryStore{saveErrorAfterPersist: true}
	cancel := validCancelStub(store)
	controller := newController(t, store, nil, cancel, nil, nil)
	if _, err := controller.Cancel(context.Background(), validCancelRequest()); ErrorCode(err) != Unavailable {
		t.Fatalf("lost response err=%v", err)
	}
	result, err := controller.Cancel(context.Background(), validCancelRequest())
	if err != nil || result.Status != Completed || len(cancel.calls) != 2 ||
		cancel.calls[0].Target.TargetID != testChild || cancel.calls[1].Target.TargetID != testJob {
		t.Fatalf("result=%+v calls=%+v err=%v", result, cancel.calls, err)
	}
}

func TestFallbackUsesOnlyApprovedEquivalentNonBroaderRoute(t *testing.T) {
	store := &memoryStore{}
	route := &routeStub{approved: validApprovedRoute(t)}
	provider := &providerStub{outcomes: []providerOutcome{
		{err: NewDependencyError(Unavailable, "primary_unavailable", true, false)}, {},
	}}
	controller := newController(t, store, nil, nil, route, provider)
	request := validInvokeRequest()
	result, err := controller.Invoke(context.Background(), request)
	if err != nil || result.Status != Completed || len(result.Attempts) != 2 || len(provider.requests) != 2 ||
		provider.requests[0].Route != "local.primary" || provider.requests[1].Route != "local.backup" ||
		result.Artifact != validArtifactRef() || len(route.requests) != 1 ||
		route.requests[0].Operation != request.Operation ||
		!reflect.DeepEqual(route.requests[0].InputRefs, request.InputRefs) ||
		route.requests[0].BudgetReservationDigest != request.BudgetReservationDigest ||
		!route.requests[0].CreatedAt.Equal(request.CreatedAt) {
		t.Fatalf("result=%+v provider_requests=%+v route_requests=%+v err=%v",
			result, provider.requests, route.requests, err)
	}
	replay, err := controller.Invoke(context.Background(), request)
	if err != nil || !replay.Replayed || len(provider.requests) != 2 {
		t.Fatalf("replay=%+v requests=%d err=%v", replay, len(provider.requests), err)
	}
}

func TestFallbackDeniesBroaderExposureCapabilityDowngradeAndUnapprovedDecisionBeforeInvocation(t *testing.T) {
	for name, mutate := range map[string]func(*ApprovedRoute){
		"broader_exposure": func(value *ApprovedRoute) {
			value.FallbackCapability = decodeCapability(t, func(snapshot *providercontract.CapabilitySnapshot) {
				snapshot.Provider.DataRoute = "approved_external"
			})
			value.FallbackQualification = decodeQualification(t, value.FallbackCapability)
		},
		"capability_downgrade": func(value *ApprovedRoute) {
			value.FallbackCapability = decodeCapability(t, func(snapshot *providercontract.CapabilitySnapshot) {
				snapshot.Limits.MaximumOutputTokens--
			})
			value.FallbackQualification = decodeQualification(t, value.FallbackCapability)
		},
		"provider_managed_primary": func(value *ApprovedRoute) {
			value.PrimaryCapability = decodeCapability(t, func(snapshot *providercontract.CapabilitySnapshot) {
				snapshot.Provider.StateMode = "provider_managed"
				snapshot.Features.StateModes = []string{"provider_managed"}
			})
			value.PrimaryQualification = decodeQualification(t, value.PrimaryCapability)
			value.FallbackCapability = value.PrimaryCapability
			value.FallbackQualification = value.PrimaryQualification
		},
		"expired_approval": func(value *ApprovedRoute) {
			value.IssuedAt = testNow.Add(-2 * time.Hour)
			value.ExpiresAt = testNow
		},
		"expired_qualification": func(value *ApprovedRoute) {
			value.FallbackQualification = decodeQualificationWithMutation(t, value.FallbackCapability,
				func(record *providercontract.QualificationRecord) {
					record.IssuedAt = "2026-07-01T00:00:00.000000000Z"
					record.ExpiresAt = "2026-08-01T00:00:00.000000000Z"
				})
		},
		"policy_mismatch": func(value *ApprovedRoute) { value.PolicyDigest = testDigest2 },
	} {
		t.Run(name, func(t *testing.T) {
			approved := validApprovedRoute(t)
			mutate(&approved)
			route := &routeStub{approved: approved}
			provider := &providerStub{}
			controller := newController(t, &memoryStore{}, nil, nil, route, provider)
			if _, err := controller.Invoke(context.Background(), validInvokeRequest()); ErrorCode(err) != DeniedCode ||
				len(provider.requests) != 0 {
				t.Fatalf("requests=%d err=%v", len(provider.requests), err)
			}
		})
	}
}

func TestFallbackNeverRunsAfterDenialCancellationTimeoutOrIndeterminateOutcome(t *testing.T) {
	for name, failure := range map[string]error{
		"denied":        NewDependencyError(DeniedCode, "provider_denied", false, false),
		"canceled":      NewDependencyError(CanceledCode, "provider_canceled", false, false),
		"timeout":       NewDependencyError(Timeout, "provider_timeout", false, false),
		"indeterminate": errors.New("connection lost after request"),
	} {
		t.Run(name, func(t *testing.T) {
			provider := &providerStub{outcomes: []providerOutcome{{err: failure}}}
			controller := newController(t, &memoryStore{}, nil, nil, nil, provider)
			result, err := controller.Invoke(context.Background(), validInvokeRequest())
			if len(provider.requests) != 1 || result.Status == Completed ||
				name == "indeterminate" && (result.Status != Uncertain || ErrorCode(err) != Conflict) {
				t.Fatalf("result=%+v requests=%d err=%v", result, len(provider.requests), err)
			}
		})
	}
}

func TestLostCompletedSaveResponseReplaysWithoutProviderDuplication(t *testing.T) {
	store := &memoryStore{saveErrorAfterPersist: true}
	provider := &providerStub{outcomes: []providerOutcome{{}}}
	controller := newController(t, store, nil, nil, nil, provider)
	if _, err := controller.Invoke(context.Background(), validInvokeRequest()); ErrorCode(err) != Unavailable {
		t.Fatalf("lost response err=%v", err)
	}
	result, err := controller.Invoke(context.Background(), validInvokeRequest())
	if err != nil || result.Status != Completed || !result.Replayed || len(provider.requests) != 1 {
		t.Fatalf("result=%+v requests=%d err=%v", result, len(provider.requests), err)
	}
}

func TestConcurrentFallbackReplayReportsInProgressWithoutCorruptingActiveAttempt(t *testing.T) {
	store := &memoryStore{}
	provider := &gatedProvider{entered: make(chan struct{}), release: make(chan struct{})}
	cancel := validCancelStub(store)
	controller, err := New(store, &workStub{}, cancel, cancel, &routeStub{approved: validApprovedRoute(t)},
		provider, &testClock{now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result Result
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, invokeErr := controller.Invoke(context.Background(), validInvokeRequest())
		finished <- outcome{result: result, err: invokeErr}
	}()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("provider was not entered")
	}
	inProgress, err := controller.Invoke(context.Background(), validInvokeRequest())
	if ErrorCode(err) != Conflict || !Retryable(err) || inProgress.Status != PrimaryAttempting ||
		store.current.Status != PrimaryAttempting {
		t.Fatalf("result=%+v state=%+v err=%v", inProgress, store.current, err)
	}
	close(provider.release)
	select {
	case first := <-finished:
		if first.err != nil || first.result.Status != Completed || store.current.Status != Completed {
			t.Fatalf("result=%+v state=%+v err=%v", first.result, store.current, first.err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider attempt did not finish")
	}
}

func TestLostBeginResponseBecomesUncertainAfterDeadlineWithoutProviderRetry(t *testing.T) {
	store := &memoryStore{beginErrorAfterPersist: true}
	provider := &providerStub{outcomes: []providerOutcome{{}}}
	controller := newController(t, store, nil, nil, nil, provider)
	request := validInvokeRequest()
	if _, err := controller.Invoke(context.Background(), request); ErrorCode(err) != Unavailable ||
		len(provider.requests) != 0 || store.current.Status != PrimaryAttempting {
		t.Fatalf("state=%+v requests=%d err=%v", store.current, len(provider.requests), err)
	}
	cancel := validCancelStub(store)
	restarted, err := New(store, &workStub{}, cancel, cancel, &routeStub{}, provider,
		&testClock{now: request.Deadline})
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.Invoke(context.Background(), request)
	if ErrorCode(err) != Conflict || result.Status != Uncertain || len(provider.requests) != 0 ||
		store.current.Status != Uncertain {
		t.Fatalf("result=%+v state=%+v requests=%d err=%v", result, store.current, len(provider.requests), err)
	}
}

func TestRecomputedRouteTamperIsDeniedOnReplay(t *testing.T) {
	store := &memoryStore{}
	provider := &providerStub{outcomes: []providerOutcome{{}}}
	controller := newController(t, store, nil, nil, nil, provider)
	if _, err := controller.Invoke(context.Background(), validInvokeRequest()); err != nil {
		t.Fatal(err)
	}
	store.current.Route.Fallback.DataRoute = "approved_external"
	forged, err := provenanceDigest(store.current.PreviousProvenanceDigest, store.current.ReasonCode, store.current)
	if err != nil {
		t.Fatal(err)
	}
	store.current.ProvenanceDigest = forged
	if _, err := controller.Invoke(context.Background(), validInvokeRequest()); ErrorCode(err) != DeniedCode {
		t.Fatalf("recomputed tamper accepted: %v", err)
	}
}
