package caselifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestInvalidCrossScopeStaleAndTamperedStateFailClosed(t *testing.T) {
	now := testNow
	clock := &testClock{now: now}
	authority := &testAuthority{now: now}
	auditor := &testAuditor{}
	store := newTestStore()
	controller, _ := New(authority, auditor, store, clock)

	invalid := validCreateCommand()
	invalid.ActorID = "missing"
	if _, err := controller.Execute(t.Context(), invalid); CodeOf(err) != InvalidInput {
		t.Fatalf("invalid command code=%s err=%v", CodeOf(err), err)
	}
	if len(authority.calls) != 0 || len(auditor.events) != 0 {
		t.Fatal("invalid input reached authority or audit")
	}

	create := validCreateCommand()
	created, err := controller.Execute(t.Context(), create)
	if err != nil {
		t.Fatal(err)
	}
	wrongScope := nextCommand(Close, created.Record, "31")
	wrongScope.Case = domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant,
		CaseID: "0199a213-3031-7031-8031-000000000031"}
	if _, err = controller.Execute(t.Context(), wrongScope); CodeOf(err) != NotFound {
		t.Fatalf("cross-case command was not isolated: %v", err)
	}
	wrongTenant := nextCommand(Close, created.Record, "32")
	wrongTenant.Case.TenantID = "0199a213-3032-7032-8032-000000000032"
	if _, err = controller.Execute(t.Context(), wrongTenant); CodeOf(err) != NotFound {
		t.Fatalf("cross-tenant command was not isolated: %v", err)
	}
	stale := nextCommand(Close, created.Record, "33")
	stale.ExpectedRevision = 2
	if _, err = controller.Execute(t.Context(), stale); CodeOf(err) != Conflict || Reason(err) != "stale_revision" {
		t.Fatalf("stale revision was not rejected: %v", err)
	}

	store.mu.Lock()
	tampered := store.current[create.Case]
	tampered.AssigneeActorID = testActor
	store.current[create.Case] = tampered
	store.mu.Unlock()
	command := nextCommand(Close, created.Record, "34")
	if _, err = controller.Execute(t.Context(), command); CodeOf(err) != Denied || Reason(err) != "stored_record_invalid" {
		t.Fatalf("tampered current record was not denied: %v", err)
	}
	if len(authority.calls) != 1 { // Only the valid create reached authority.
		t.Fatalf("fail-closed checks unexpectedly reached authority: %d", len(authority.calls))
	}
}

func TestCancellationAndTimeoutReturnTypedFailuresWithoutMutation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := newTestStore()
	auditor := &testAuditor{}
	ctx, cancel := context.WithCancel(context.Background())
	cancelingAuthority := authorityFunc(func(_ context.Context, _ AuthorizationRequest) (Decision, error) {
		cancel()
		return Decision{}, context.Canceled
	})
	controller, _ := New(cancelingAuthority, auditor, store, &testClock{now: now})
	command := validCreateCommand()
	command.Deadline = now.Add(time.Hour)
	retainUntil := now.Add(24 * time.Hour)
	command.RetainUntil = &retainUntil
	if _, err := controller.Execute(ctx, command); CodeOf(err) != Canceled {
		t.Fatalf("cancellation code=%s err=%v", CodeOf(err), err)
	}
	if _, found, _ := store.Load(context.Background(), command.Case); found {
		t.Fatal("canceled command mutated state")
	}

	timeoutStore := newTestStore()
	timeoutAuthority := authorityFunc(func(ctx context.Context, _ AuthorizationRequest) (Decision, error) {
		<-ctx.Done()
		return Decision{}, ctx.Err()
	})
	timeoutController, _ := New(timeoutAuthority, auditor, timeoutStore, &testClock{now: now})
	timed := cloneCommand(command)
	timed.RequestID = "0199a213-3035-7035-8035-000000000035"
	timed.IdempotencyKey = "case-timeout"
	timed.Deadline = now.Add(20 * time.Millisecond)
	if _, err := timeoutController.Execute(context.Background(), timed); CodeOf(err) != Timeout {
		t.Fatalf("timeout code=%s err=%v", CodeOf(err), err)
	}
	if _, found, _ := timeoutStore.Load(context.Background(), timed.Case); found {
		t.Fatal("timed out command mutated state")
	}
}

func TestConcurrentRevisionHasExactlyOneWinner(t *testing.T) {
	now := testNow
	clock := &testClock{now: now}
	authority := &testAuthority{now: now}
	auditor := &testAuditor{}
	store := newTestStore()
	controller, _ := New(authority, auditor, store, clock)
	created, err := controller.Execute(t.Context(), validCreateCommand())
	if err != nil {
		t.Fatal(err)
	}
	commands := []Command{nextCommand(Close, created.Record, "41"), nextCommand(Close, created.Record, "42")}
	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, len(commands))
	var start sync.WaitGroup
	start.Add(1)
	for _, command := range commands {
		go func(value Command) {
			start.Wait()
			result, executeErr := controller.Execute(context.Background(), value)
			results <- outcome{result: result, err: executeErr}
		}(command)
	}
	start.Done()
	successes, conflicts := 0, 0
	for range commands {
		value := <-results
		if value.err == nil && value.result.Record.State == Closed && value.result.Record.Revision == 2 {
			successes++
		} else if CodeOf(value.err) == Conflict {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent result=%+v err=%v", value.result, value.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	current, found, err := store.Load(t.Context(), created.Record.Case)
	if err != nil || !found || current.State != Closed || current.Revision != 2 || validateRecord(current) != nil {
		t.Fatalf("current=%+v found=%v err=%v", current, found, err)
	}
}
