package queryevidence

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

func TestStartFailsClosedOnMissingOrSubstitutedArtifact(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	t.Run("source missing", func(t *testing.T) {
		controller, ingest, store, _, command := fixture(t, native)
		_, err := controller.Start(context.Background(), command, nil)
		if Code(err) != InvalidInput || ingest.calls != 0 || store.appends != 0 {
			t.Fatal("missing source did not fail before side effects")
		}
	})
	t.Run("binding substitution", func(t *testing.T) {
		controller, ingest, store, _, command := fixture(t, native)
		ingest.binding.ManifestProvenanceDigest = "sha256:" + string(make([]byte, 64))
		_, err := controller.Start(context.Background(), command, &sourceStub{data: native})
		if Code(err) != Conflict || store.appends != 0 {
			t.Fatal("substituted binding was accepted")
		}
	})
}

func TestReplayRejectsChangedClassification(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, _, _, command := fixture(t, native)
	if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
		t.Fatal(err)
	}
	command.Classification = "confidential"
	_, err := controller.Start(context.Background(), command, nil)
	if Code(err) != Conflict || Reason(err) != "idempotency_conflict" {
		t.Fatal("changed idempotency intent was accepted")
	}
}

func TestTransitionRejectsForkRegressionAndUnknownCompleteness(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, _, _, command := fixture(t, native)
	if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
		t.Fatal(err)
	}

	fork := signedSession(2, digest("wrong-head"), "running", "page_available", queryruntime.Usage{RowsScanned: 2, RowsReturned: 1, PagesReturned: 1})
	_, err := controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "fork", Event: "page", RuntimeSession: fork,
		Completeness: "running", ReasonCode: "page_available", Deadline: command.Deadline})
	if Code(err) != Conflict || Reason(err) != "transition_lineage_invalid" {
		t.Fatal("chain fork was accepted")
	}

	unknown := signedSession(2, command.RuntimeSession.SessionDigest, "running", "vendor_unknown", queryruntime.Usage{})
	_, err = controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "unknown", Event: "uncertain", RuntimeSession: unknown,
		Completeness: "unknown", ReasonCode: "vendor_unknown", Deadline: command.Deadline})
	if Code(err) != InvalidInput {
		t.Fatal("unknown completeness was accepted instead of explicit uncertainty")
	}

	page := signedSession(2, command.RuntimeSession.SessionDigest, "running", "page_available", queryruntime.Usage{RowsScanned: 10, RowsReturned: 5, BytesReturned: 50, PagesReturned: 1})
	if _, err = controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "page", Event: "page", RuntimeSession: page,
		Completeness: "running", ReasonCode: "page_available", Deadline: command.Deadline}); err != nil {
		t.Fatal(err)
	}
	regression := signedSession(3, page.SessionDigest, "running", "page_available", queryruntime.Usage{RowsScanned: 9, RowsReturned: 4, BytesReturned: 40, PagesReturned: 2})
	_, err = controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "regression", Event: "page", RuntimeSession: regression,
		Completeness: "running", ReasonCode: "page_available", Deadline: command.Deadline})
	if Code(err) != Conflict {
		t.Fatal("statistics regression was accepted")
	}
}

func TestTerminalCompletenessAndCancellationRemainExplicit(t *testing.T) {
	tests := []struct{ name, status, event string }{{"partial", "partial", "partial"}, {"truncated", "truncated", "truncated"}, {"uncertain", "uncertain", "uncertain"}, {"failed", "failed", "failed"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := []byte("SecurityEvent | take 10")
			controller, _, _, _, command := fixture(t, native)
			if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
				t.Fatal(err)
			}
			session := signedSession(2, command.RuntimeSession.SessionDigest, test.status, "vendor_"+test.status, queryruntime.Usage{})
			result, err := controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: test.name, Event: test.event,
				RuntimeSession: session, Completeness: test.status, ReasonCode: "vendor_" + test.status, Deadline: command.Deadline})
			if err != nil || result.Record.Completeness != test.status {
				t.Fatal("terminal completeness changed")
			}
		})
	}

	t.Run("confirmed cancellation", func(t *testing.T) {
		native := []byte("SecurityEvent | take 10")
		controller, _, _, _, command := fixture(t, native)
		if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
			t.Fatal(err)
		}
		session := signedSession(2, command.RuntimeSession.SessionDigest, "canceled", "vendor_canceled", queryruntime.Usage{})
		session.CancellationIntentDigest = digest("cancel-intent")
		session = resignSession(session)
		_, err := controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "cancel", Event: "canceled", RuntimeSession: session,
			Completeness: "canceled", ReasonCode: "vendor_canceled", CancellationIntentDigest: session.CancellationIntentDigest,
			CancellationOutcomeDigest: digest("cancel-outcome"), Deadline: command.Deadline})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestCancellationAndDependencyOutageDoNotInventEvidence(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	t.Run("caller canceled", func(t *testing.T) {
		controller, ingest, store, audit, command := fixture(t, native)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := controller.Start(ctx, command, &sourceStub{data: native})
		if Code(err) != Canceled || ingest.calls != 0 || store.appends != 0 || len(audit.events) != 0 {
			t.Fatal("canceled request created evidence")
		}
	})
	t.Run("append outage", func(t *testing.T) {
		controller, ingest, store, audit, command := fixture(t, native)
		store.appendErr = errors.New("lost response")
		_, err := controller.Start(context.Background(), command, &sourceStub{data: native})
		if Code(err) != Unavailable || ingest.calls != 1 || len(audit.events) != 0 {
			t.Fatal("append outage inferred a durable record")
		}
	})
}

func TestConcurrentSuccessorsCannotForkChain(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, store, _, command := fixture(t, native)
	if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
		t.Fatal(err)
	}
	session := signedSession(2, command.RuntimeSession.SessionDigest, "running", "page_available", queryruntime.Usage{RowsScanned: 1, RowsReturned: 1, PagesReturned: 1})
	commands := []TransitionCommand{
		{IdempotencyKey: "successor-a", Event: "page", RuntimeSession: session, Completeness: "running", ReasonCode: "page_available", Deadline: command.Deadline},
		{IdempotencyKey: "successor-b", Event: "page", RuntimeSession: session, Completeness: "running", ReasonCode: "page_available", Deadline: command.Deadline},
	}
	var wg sync.WaitGroup
	wg.Add(2)
	outcomes := make(chan error, 2)
	for index := range commands {
		go func(value TransitionCommand) {
			defer wg.Done()
			_, err := controller.Transition(context.Background(), value)
			outcomes <- err
		}(commands[index])
	}
	wg.Wait()
	close(outcomes)
	success, conflict := 0, 0
	for err := range outcomes {
		if err == nil {
			success++
		} else if Code(err) == Conflict || Code(err) == Unavailable {
			conflict++
		}
	}
	if success != 1 || conflict != 1 || store.head == nil || store.head.Revision != 2 {
		t.Fatal("concurrent successors forked or both failed")
	}
}

func TestDecodeRecordRejectsTamperingAndUnknownFields(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, _, _, command := fixture(t, native)
	result, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.Record)
	if _, _, err = DecodeRecord(context.Background(), encoded); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(encoded, &object)
	object["native_text"] = "leak"
	changed, _ := json.Marshal(object)
	if _, _, err = DecodeRecord(context.Background(), changed); Code(err) != InvalidInput {
		t.Fatal("unknown plaintext field was accepted")
	}
	object = map[string]any{}
	_ = json.Unmarshal(encoded, &object)
	object["reason_code"] = "changed"
	changed, _ = json.Marshal(object)
	if _, _, err = DecodeRecord(context.Background(), changed); Code(err) != Conflict {
		t.Fatal("tampered record was accepted")
	}
}
