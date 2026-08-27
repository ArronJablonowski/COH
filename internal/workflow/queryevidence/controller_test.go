package queryevidence

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

func TestStartPersistsEncryptedBindingWithoutNativeText(t *testing.T) {
	native := []byte("SecurityEvent | where Account contains 'secret-user'")
	controller, ingest, store, audit, command := fixture(t, native)
	result, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result.Record)
	if strings.Contains(string(encoded), "SecurityEvent") || strings.Contains(string(encoded), "secret-user") {
		t.Fatal("plaintext leaked into record")
	}
	if result.Record.NativeQuery.Artifact.Digest != command.NativeQueryDigest || result.Record.QueryDigest != command.QueryDigest || ingest.calls != 1 || store.appends != 1 || len(audit.events) != 1 {
		t.Fatal("start evidence not bound or persisted")
	}
}

func TestStartReplayDoesNotReingest(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, ingest, _, audit, command := fixture(t, native)
	first, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := controller.Start(context.Background(), command, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Record.RecordDigest != first.Record.RecordDigest || ingest.calls != 1 || len(audit.events) != 2 {
		t.Fatal("exact replay was not recovered")
	}
}

func TestTransitionBindsRuntimeResultAndCompleteness(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, _, _, command := fixture(t, native)
	started, err := controller.Start(context.Background(), command, &sourceStub{data: native})
	if err != nil {
		t.Fatal(err)
	}
	usage := queryruntime.Usage{RowsScanned: 10, RowsReturned: 10, BytesReturned: 200, DurationMillis: 50, PagesReturned: 1}
	session := signedSession(2, command.RuntimeSession.SessionDigest, "complete", "vendor_complete", usage)
	session.LastPageDigest = digest("result")
	// Re-sign after adding the result digest.
	session = resignSession(session)
	resultBinding := artifact("result", 200)
	result, err := controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "result-1", Event: "result", RuntimeSession: session,
		Result: &resultBinding, ResultDigest: resultBinding.Artifact.Digest, Completeness: "complete", ReasonCode: "vendor_complete", Deadline: command.Deadline})
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.PreviousProvenanceDigest != started.Record.ProvenanceDigest || result.Record.Revision != 2 || result.Record.ResultDigest != resultBinding.Artifact.Digest || result.Record.Completeness != "complete" {
		t.Fatal("result transition not fully bound")
	}
	replay, err := controller.Transition(context.Background(), TransitionCommand{IdempotencyKey: "result-1", Event: "result", RuntimeSession: session,
		Result: &resultBinding, ResultDigest: resultBinding.Artifact.Digest, Completeness: "complete", ReasonCode: "vendor_complete", Deadline: command.Deadline})
	if err != nil || !replay.Replayed {
		t.Fatal("transition replay failed")
	}
}

func TestRecordQuerySessionUsesNarrowRuntimePort(t *testing.T) {
	native := []byte("SecurityEvent | take 10")
	controller, _, _, _, command := fixture(t, native)
	if _, err := controller.Start(context.Background(), command, &sourceStub{data: native}); err != nil {
		t.Fatal(err)
	}
	session := signedSession(2, command.RuntimeSession.SessionDigest, "running", "page_available", queryruntime.Usage{RowsScanned: 1, RowsReturned: 1, BytesReturned: 10, PagesReturned: 1})
	session.LastPageDigest = digest("page")
	session = resignSession(session)
	if err := controller.RecordQuerySession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
}

func resignSession(value queryruntime.Session) queryruntime.Session {
	value.SessionDigest = ""
	encoded, _ := json.Marshal(value)
	canonical, _ := canonicalRuntime(encoded)
	value.SessionDigest = canonical
	return value
}
