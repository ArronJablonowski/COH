package retrievalguard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHostileContentIsInspectedAuditedAndReturnedOnlyAsUntrustedData(t *testing.T) {
	controller, clock, authority, inspector, verifier, auditor, store := newFixture()
	request := validRequest(clock.now)
	result, err := controller.Inspect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Inspection.Trust != UntrustedContent || result.Inspection.Sanitized.MediaType != "application/json" || len(result.Inspection.Findings) != 2 || result.AuditEventDigest == "" || result.ProvenanceDigest == "" {
		t.Fatalf("result=%+v", result)
	}
	if authority.calls != 1 || inspector.calls != 1 || verifier.calls != 1 || store.calls != 1 || auditor.calls != 1 {
		t.Fatalf("calls authority=%d inspector=%d verifier=%d store=%d audit=%d", authority.calls, inspector.calls, verifier.calls, store.calls, auditor.calls)
	}
	for _, event := range auditor.events {
		if event.Outcome != "allowed" || event.ReasonCode != "content_sanitized" || event.SubjectDigest != result.Inspection.Sanitized.Digest || len(event.EvidenceDigests) < 6 {
			t.Fatalf("event=%+v", event)
		}
	}
}

func TestPolicyDenialAndRevocationAreAuditedBeforeReturn(t *testing.T) {
	controller, clock, authority, inspector, _, auditor, store := newFixture()
	authority.allow = false
	_, err := controller.Inspect(context.Background(), validRequest(clock.now))
	if CodeOf(err) != Denied || Reason(err) != "policy_denied" {
		t.Fatalf("err=%v", err)
	}
	if inspector.calls != 0 || store.calls != 0 || auditor.calls != 1 {
		t.Fatalf("inspector=%d store=%d audit=%d", inspector.calls, store.calls, auditor.calls)
	}
	for _, event := range auditor.events {
		if event.Outcome != "denied" || event.ReasonCode != "policy_denied" {
			t.Fatalf("event=%+v", event)
		}
	}
}

func TestExactReplayRechecksAuthorityArtifactAndAudit(t *testing.T) {
	controller, clock, authority, inspector, verifier, auditor, _ := newFixture()
	request := validRequest(clock.now)
	first, err := controller.Inspect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := controller.Inspect(context.Background(), request)
	if err != nil || !replay.Replayed || replay.ProvenanceDigest != first.ProvenanceDigest {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if authority.calls != 2 || inspector.calls != 1 || verifier.calls != 2 || auditor.calls != 3 || len(auditor.events) != 2 {
		t.Fatalf("calls authority=%d inspector=%d verifier=%d audit=%d events=%d", authority.calls, inspector.calls, verifier.calls, auditor.calls, len(auditor.events))
	}
	seenReplay := false
	for _, event := range auditor.events {
		if event.ReasonCode == "replay_authorized" {
			seenReplay = true
		}
	}
	if !seenReplay {
		t.Fatal("fresh replay authorization was not audited")
	}
	authority.allow = false
	if _, err = controller.Inspect(context.Background(), request); CodeOf(err) != Denied {
		t.Fatalf("revoked replay err=%v", err)
	}
}

func TestChangedReplayTamperPartialAndLostResponseFailClosed(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		controller, clock, _, _, _, auditor, _ := newFixture()
		request := validRequest(clock.now)
		if _, err := controller.Inspect(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		changed := request
		changed.Source.Artifact.Digest = digest("changed", nil)
		if _, err := controller.Inspect(context.Background(), changed); CodeOf(err) != Denied || Reason(err) != "changed_replay" {
			t.Fatalf("err=%v", err)
		}
		if auditor.calls != 2 {
			t.Fatalf("audit calls=%d", auditor.calls)
		}
	})
	t.Run("decision", func(t *testing.T) {
		controller, clock, authority, _, _, _, _ := newFixture()
		authority.tamper = true
		if _, err := controller.Inspect(context.Background(), validRequest(clock.now)); CodeOf(err) != Denied || Reason(err) != "decision_invalid" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("partial", func(t *testing.T) {
		controller, clock, _, inspector, _, auditor, store := newFixture()
		inspector.result.Complete = false
		if _, err := controller.Inspect(context.Background(), validRequest(clock.now)); CodeOf(err) != Denied {
			t.Fatalf("err=%v", err)
		}
		if auditor.calls != 1 || store.calls != 0 {
			t.Fatalf("audit=%d store=%d", auditor.calls, store.calls)
		}
	})
	t.Run("lost-response", func(t *testing.T) {
		controller, clock, _, inspector, _, auditor, store := newFixture()
		store.lost = true
		request := validRequest(clock.now)
		if _, err := controller.Inspect(context.Background(), request); CodeOf(err) != Unavailable {
			t.Fatalf("err=%v", err)
		}
		result, err := controller.Inspect(context.Background(), request)
		if err != nil || !result.Replayed || inspector.calls != 1 || auditor.calls != 2 {
			t.Fatalf("result=%+v err=%v inspector=%d audit=%d", result, err, inspector.calls, auditor.calls)
		}
	})
	t.Run("replay-artifact", func(t *testing.T) {
		controller, clock, _, _, verifier, auditor, _ := newFixture()
		request := validRequest(clock.now)
		if _, err := controller.Inspect(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		verifier.err = newError(Unavailable, "artifact_missing", true, nil)
		if _, err := controller.Inspect(context.Background(), request); CodeOf(err) != Unavailable || Reason(err) != "sanitized_unavailable" {
			t.Fatalf("err=%v", err)
		}
		seen := false
		for _, event := range auditor.events {
			if event.Outcome == "denied" && event.ReasonCode == "sanitized_unavailable" {
				seen = true
			}
		}
		if !seen {
			t.Fatal("replay artifact failure was not audited")
		}
	})
}

func TestAuditFailureCancellationTimeoutAndRecovery(t *testing.T) {
	t.Run("audit", func(t *testing.T) {
		controller, clock, _, inspector, _, auditor, _ := newFixture()
		auditor.err = errors.New("audit down")
		request := validRequest(clock.now)
		if _, err := controller.Inspect(context.Background(), request); CodeOf(err) != Unavailable || Reason(err) != "audit_unavailable" {
			t.Fatalf("err=%v", err)
		}
		auditor.err = nil
		result, err := controller.Inspect(context.Background(), request)
		if err != nil || !result.Replayed || inspector.calls != 1 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		controller, clock, _, _, _, _, _ := newFixture()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := controller.Inspect(ctx, validRequest(clock.now)); CodeOf(err) != Canceled || !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		controller, clock, _, _, _, _, _ := newFixture()
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if _, err := controller.Inspect(ctx, validRequest(clock.now)); CodeOf(err) != Timeout || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestAllRetrievedSourceKindsAreClosedAndUntrusted(t *testing.T) {
	for _, kind := range []SourceKind{LogSource, DocumentSource, FeedSource, QueryOutputSource, ToolOutputSource, ToolErrorSource, MemorySource, ReportSource, AttachmentSource} {
		t.Run(string(kind), func(t *testing.T) {
			controller, clock, authority, inspector, _, _, _ := newFixture()
			request := validRequest(clock.now)
			request.Source.Kind = kind
			result, err := controller.Inspect(context.Background(), request)
			if err != nil || result.Inspection.Trust != UntrustedContent ||
				authority.last.Source.Kind != kind || inspector.request.Source.Kind != kind ||
				authority.last.Case != request.Case || authority.last.TaskID != request.TaskID ||
				authority.last.ActorID != request.ActorID || authority.last.ActorRevision != request.ActorRevision {
				t.Fatalf("kind=%s authority=%+v inspection=%+v result=%+v err=%v", kind, authority.last, inspector.request, result, err)
			}
		})
	}
	request := validRequest(testNow)
	request.Source.Kind = "socket"
	if err := validateRequest(request, testNow); CodeOf(err) != InvalidInput {
		t.Fatalf("unknown kind err=%v", err)
	}
}
