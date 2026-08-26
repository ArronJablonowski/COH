package memorynamespace

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFourNamespacesRemainClassBound(t *testing.T) {
	for _, namespace := range []Namespace{SessionMemory, CaseMemory, AnalystPreferenceMemory, ReviewedOrganizationMemory} {
		t.Run(string(namespace), func(t *testing.T) {
			clock := &testClock{now: testNow}
			controller, authority, reviews, stores := newControllerForTest(clock)
			request := validPut(namespace, clock.now)
			written, err := controller.Put(context.Background(), request)
			if err != nil || written.Replayed || written.Record.Namespace != namespace || written.Record.Revision != 1 {
				t.Fatalf("Put=%+v err=%v", written, err)
			}
			read, err := controller.Get(context.Background(), validGet(request, clock.now))
			if err != nil || read.Record.ProvenanceDigest != written.Record.ProvenanceDigest {
				t.Fatalf("Get=%+v err=%v", read, err)
			}
			for candidate, store := range stores {
				want := 0
				if candidate == namespace {
					want = 1
				}
				if len(store.current) != want {
					t.Fatalf("store %s count=%d want=%d", candidate, len(store.current), want)
				}
			}
			if authority.calls != 2 {
				t.Fatalf("access calls=%d", authority.calls)
			}
			wantReviews := 0
			if namespace == ReviewedOrganizationMemory {
				wantReviews = 2
			}
			if reviews.calls != wantReviews {
				t.Fatalf("review calls=%d want=%d", reviews.calls, wantReviews)
			}
		})
	}
}

func TestWriteReplayUpdateAndStaleRevision(t *testing.T) {
	clock := &testClock{now: testNow}
	controller, _, _, _ := newControllerForTest(clock)
	request := validPut(CaseMemory, clock.now)
	first, err := controller.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := controller.Put(context.Background(), request)
	if err != nil || !replay.Replayed || replay.Record.ProvenanceDigest != first.Record.ProvenanceDigest {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	changed := request
	changed.Value.Digest = digest("other", nil)
	if _, err = controller.Put(context.Background(), changed); CodeOf(err) != Denied || Reason(err) != "changed_replay" {
		t.Fatalf("changed replay err=%v", err)
	}
	update := request
	update.RequestID = testSession
	update.IdempotencyKey = "write-2"
	update.ExpectedRevision = 1
	update.Value.Digest = digest("updated", nil)
	second, err := controller.Put(context.Background(), update)
	if err != nil || second.Record.Revision != 2 || second.Record.PreviousProvenanceDigest != first.Record.ProvenanceDigest {
		t.Fatalf("update=%+v err=%v", second, err)
	}
	stale := update
	stale.RequestID = testReviewer
	stale.IdempotencyKey = "write-3"
	stale.Value.Digest = digest("stale", nil)
	if _, err = controller.Put(context.Background(), stale); CodeOf(err) != Conflict {
		t.Fatalf("stale err=%v", err)
	}
}

func TestOwnershipScopeRetentionReviewAndTamperDeny(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		clock := &testClock{now: testNow}
		controller, _, _, _ := newControllerForTest(clock)
		request := validPut(AnalystPreferenceMemory, clock.now)
		request.ActorID = testReviewer
		if _, err := controller.Put(context.Background(), request); CodeOf(err) != Denied {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cross-case", func(t *testing.T) {
		clock := &testClock{now: testNow}
		controller, _, _, _ := newControllerForTest(clock)
		request := validPut(CaseMemory, clock.now)
		if _, err := controller.Put(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		read := validGet(request, clock.now)
		read.Scope.CaseID = testSession
		if _, err := controller.Get(context.Background(), read); CodeOf(err) != NotFound {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		clock := &testClock{now: testNow}
		controller, _, _, _ := newControllerForTest(clock)
		request := validPut(CaseMemory, clock.now)
		request.Retention.ExpiresAt = clock.now.Add(time.Minute)
		if _, err := controller.Put(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		clock.now = clock.now.Add(2 * time.Minute)
		read := validGet(request, clock.now)
		if _, err := controller.Get(context.Background(), read); CodeOf(err) != Denied || Reason(err) != "memory_expired" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("review-revoked", func(t *testing.T) {
		clock := &testClock{now: testNow}
		controller, _, reviews, _ := newControllerForTest(clock)
		request := validPut(ReviewedOrganizationMemory, clock.now)
		if _, err := controller.Put(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		reviews.allow = false
		if _, err := controller.Get(context.Background(), validGet(request, clock.now)); CodeOf(err) != Denied || Reason(err) != "review_revoked" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("tamper", func(t *testing.T) {
		clock := &testClock{now: testNow}
		controller, _, _, stores := newControllerForTest(clock)
		request := validPut(SessionMemory, clock.now)
		if _, err := controller.Put(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		stores[SessionMemory].tamper = true
		if _, err := controller.Get(context.Background(), validGet(request, clock.now)); CodeOf(err) != Denied {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestPolicyDenialDecisionTamperCancellationAndTimeout(t *testing.T) {
	clock := &testClock{now: testNow}
	controller, authority, _, _ := newControllerForTest(clock)
	request := validPut(CaseMemory, clock.now)
	authority.allow = false
	if _, err := controller.Put(context.Background(), request); CodeOf(err) != Denied || Reason(err) != "memory_denied" {
		t.Fatalf("denial err=%v", err)
	}
	authority.allow = true
	authority.tamper = true
	if _, err := controller.Put(context.Background(), request); CodeOf(err) != Denied || Reason(err) != "access_decision_invalid" {
		t.Fatalf("tamper err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.Put(canceled, request); CodeOf(err) != Canceled || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := controller.Put(expired, request); CodeOf(err) != Timeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err=%v", err)
	}
}

func TestConstructorRejectsCrossClassStoreWiring(t *testing.T) {
	clock := &testClock{now: testNow}
	authority := &testAuthority{now: clock, allow: true}
	reviews := &testReviewAuthority{now: clock, allow: true}
	caseStore := newMemoryStore(CaseMemory)
	if _, err := New(caseStore, caseStore, newMemoryStore(AnalystPreferenceMemory), newMemoryStore(ReviewedOrganizationMemory), authority, reviews, clock); CodeOf(err) != Denied {
		t.Fatalf("err=%v", err)
	}
}

func TestCrossClassAndUnsafeValueTypesAreRejected(t *testing.T) {
	clock := &testClock{now: testNow}
	controller, _, _, _ := newControllerForTest(clock)
	request := validPut(SessionMemory, clock.now)
	for _, valueType := range []string{"case_memory_reference", "prompt", "query_handle", "executor"} {
		candidate := request
		candidate.ValueType = valueType
		if _, err := controller.Put(context.Background(), candidate); CodeOf(err) != InvalidInput {
			t.Fatalf("value type %q accepted: %v", valueType, err)
		}
	}
}
