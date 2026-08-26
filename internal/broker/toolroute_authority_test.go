package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
)

func TestToolRouteSuccessBindsPolicyApprovalAuditAndReplaysWithoutDispatch(t *testing.T) {
	fixture := newToolRouteFixture(t)
	receipt, err := fixture.authority.Submit(context.Background(), fixture.intent)
	if err != nil || receipt.Outcome != "succeeded" || fixture.connector.calls != 1 ||
		fixture.store.current.Status != routeSucceeded || fixture.store.current.PreDispatchDecisionDigest == "" ||
		fixture.store.current.ApprovalFingerprintDigest == "" || fixture.store.current.DispatchAuditID == "" ||
		fixture.store.current.CompletionAuditID == "" || len(fixture.predispatch.audit.events) != 3 {
		t.Fatalf("receipt=%+v state=%+v connector=%d audits=%d err=%v", receipt,
			fixture.store.current, fixture.connector.calls, len(fixture.predispatch.audit.events), err)
	}
	replayed, err := fixture.authority.Submit(context.Background(), fixture.intent)
	if err != nil || replayed != receipt || fixture.connector.calls != 1 || fixture.resolver.calls != 1 ||
		len(fixture.predispatch.audit.events) != 3 {
		t.Fatalf("replayed=%+v connector=%d resolver=%d audits=%d err=%v", replayed,
			fixture.connector.calls, fixture.resolver.calls, len(fixture.predispatch.audit.events), err)
	}
}

func TestToolRouteDefaultDenyCoversTamperStaleIdentityStopAndApprovalReplay(t *testing.T) {
	tests := map[string]func(*testing.T, *toolRouteFixture){
		"intent_tamper": func(_ *testing.T, fixture *toolRouteFixture) {
			fixture.intent.TargetDigest = gateDigest("c")
		},
		"actor_revoked": func(_ *testing.T, fixture *toolRouteFixture) {
			fixture.resolver.command.PolicyActor.Active = false
		},
		"policy_stale": func(_ *testing.T, fixture *toolRouteFixture) {
			fixture.predispatch.policy.mutate = func(decision *policy.Decision) {
				decision.EvaluatedAt = testTime.Add(-time.Hour).Format(timestampLayout)
			}
		},
		"emergency_stop": func(_ *testing.T, fixture *toolRouteFixture) {
			fixture.stop.err = lifecycle.NewError(lifecycle.Denied, "emergency_stop_active")
		},
		"revoked_after_authorization": func(_ *testing.T, fixture *toolRouteFixture) {
			fixture.stop.failAt = 2
			fixture.stop.err = lifecycle.NewError(lifecycle.Denied, "emergency_stop_active")
		},
		"approval_replay": func(t *testing.T, fixture *toolRouteFixture) {
			if _, err := fixture.predispatch.gate.authorize(context.Background(), fixture.predispatch.command); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newToolRouteFixture(t)
			mutate(t, fixture)
			receipt, err := fixture.authority.Submit(context.Background(), fixture.intent)
			if err != nil || receipt.Outcome != "denied" || fixture.connector.calls != 0 ||
				fixture.store.current.Status != routeDenied || fixture.store.current.CompletionAuditID == "" {
				t.Fatalf("receipt=%+v state=%+v connector=%d err=%v", receipt,
					fixture.store.current, fixture.connector.calls, err)
			}
		})
	}
}

func TestToolRouteRejectsInvalidInputScopeDriftAndNonConsequentialTierBeforeDispatch(t *testing.T) {
	t.Run("invalid_input", func(t *testing.T) {
		fixture := newToolRouteFixture(t)
		fixture.intent.Tool = "secret/bearing"
		if _, err := fixture.authority.Submit(context.Background(), fixture.intent); routeCode(err) != routeCodeInvalidInput ||
			fixture.resolver.calls != 0 || fixture.connector.calls != 0 || fixture.store.current.OperationID != "" {
			t.Fatalf("state=%+v resolver=%d connector=%d err=%v", fixture.store.current,
				fixture.resolver.calls, fixture.connector.calls, err)
		}
	})
	t.Run("scope_drift", func(t *testing.T) {
		fixture := newToolRouteFixture(t)
		fixture.intent.Case.CaseID = "0198d6c4-9999-7999-8999-999999999999"
		receipt, err := fixture.authority.Submit(context.Background(), fixture.intent)
		if err != nil || receipt.Outcome != "denied" || fixture.connector.calls != 0 ||
			fixture.store.current.Status != routeDenied {
			t.Fatalf("receipt=%+v state=%+v connector=%d err=%v", receipt,
				fixture.store.current, fixture.connector.calls, err)
		}
	})
	t.Run("non_consequential_tier", func(t *testing.T) {
		fixture := newToolRouteFixtureTier(t, "T1")
		receipt, err := fixture.authority.Submit(context.Background(), fixture.intent)
		if err != nil || receipt.Outcome != "denied" || fixture.connector.calls != 0 ||
			fixture.store.current.Status != routeDenied {
			t.Fatalf("receipt=%+v state=%+v connector=%d err=%v", receipt,
				fixture.store.current, fixture.connector.calls, err)
		}
	})
}

func TestToolRouteCorruptDurableStateIsDeniedBeforeTrustedResolution(t *testing.T) {
	fixture := newToolRouteFixture(t)
	if _, err := fixture.authority.Submit(context.Background(), fixture.intent); err != nil {
		t.Fatal(err)
	}
	fixture.store.current.ProvenanceDigest = gateDigest("0")
	fixture.store.current.ActionOwnerActorRevision++
	if _, err := fixture.authority.Submit(context.Background(), fixture.intent); routeCode(err) != routeCodeDenied ||
		fixture.connector.calls != 1 || fixture.resolver.calls != 1 {
		t.Fatalf("connector=%d resolver=%d err=%v", fixture.connector.calls, fixture.resolver.calls, err)
	}
}

func TestToolRouteDispatchCrashBecomesUncertainAndNeverRedispatches(t *testing.T) {
	fixture := newToolRouteFixture(t)
	fixture.store.failSave = 3
	_, err := fixture.authority.Submit(context.Background(), fixture.intent)
	var classified interface {
		ActivityOutcome() string
		DispatchIndeterminate() bool
	}
	if !errors.As(err, &classified) || !classified.DispatchIndeterminate() || fixture.connector.calls != 1 ||
		fixture.store.current.Status != routeDispatching {
		t.Fatalf("state=%+v connector=%d err=%v", fixture.store.current, fixture.connector.calls, err)
	}
	restarted, restartErr := newToolRouteAuthority(fixture.store, fixture.resolver, fixture.predispatch.gate,
		fixture.stop, fixture.connector, fixture.predispatch.audit, &fakeClock{now: testTime},
		toolRouteIdentity{ActorID: ownerID, ActorRevision: owner().Revision})
	if restartErr != nil {
		t.Fatal(restartErr)
	}
	receipt, err := restarted.Submit(context.Background(), fixture.intent)
	if err != nil || receipt.Outcome != "uncertain" || fixture.connector.calls != 1 ||
		fixture.store.current.Status != routeUncertain {
		t.Fatalf("receipt=%+v state=%+v connector=%d err=%v", receipt,
			fixture.store.current, fixture.connector.calls, err)
	}
}

func TestToolRouteConnectorFailureOrInvalidReceiptIsUncertain(t *testing.T) {
	for name, mutate := range map[string]func(*toolRouteFixture){
		"connector_error": func(fixture *toolRouteFixture) { fixture.connector.err = errors.New("wire lost") },
		"invalid_receipt": func(fixture *toolRouteFixture) { fixture.connector.receipt.IntentDigest = gateDigest("d") },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newToolRouteFixture(t)
			mutate(fixture)
			receipt, err := fixture.authority.Submit(context.Background(), fixture.intent)
			if err != nil || receipt.Outcome != "uncertain" || fixture.connector.calls != 1 ||
				fixture.store.current.Status != routeUncertain {
				t.Fatalf("receipt=%+v state=%+v calls=%d err=%v", receipt,
					fixture.store.current, fixture.connector.calls, err)
			}
		})
	}
}

func TestToolRouteCancellationTimeoutAndAuditFailureStayFailClosed(t *testing.T) {
	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
		"canceled": func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		},
		"timeout": func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), testTime.Add(-time.Second))
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newToolRouteFixture(t)
			ctx, cancel := makeContext()
			defer cancel()
			_, err := fixture.authority.Submit(ctx, fixture.intent)
			if routeCode(err) == routeCodeUnavailable || fixture.connector.calls != 0 ||
				len(fixture.predispatch.audit.events) != 1 {
				t.Fatalf("connector=%d audits=%d err=%v", fixture.connector.calls,
					len(fixture.predispatch.audit.events), err)
			}
		})
	}

	fixture := newToolRouteFixture(t)
	fixture.predispatch.audit.fail = true
	if _, err := fixture.authority.Submit(context.Background(), fixture.intent); routeCode(err) != routeCodeUnavailable ||
		fixture.connector.calls != 0 || fixture.store.current.Status != routeAuthorizing {
		t.Fatalf("state=%+v connector=%d err=%v", fixture.store.current, fixture.connector.calls, err)
	}
}

func TestToolRouteReplayRejectsOneByteIntentChange(t *testing.T) {
	fixture := newToolRouteFixture(t)
	if _, err := fixture.authority.Submit(context.Background(), fixture.intent); err != nil {
		t.Fatal(err)
	}
	fixture.intent.ArgumentDigest = gateDigest("e")
	if _, err := fixture.authority.Submit(context.Background(), fixture.intent); routeCode(err) != routeCodeDenied ||
		fixture.connector.calls != 1 {
		t.Fatalf("connector=%d err=%v", fixture.connector.calls, err)
	}
}
