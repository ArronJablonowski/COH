package modelsurface

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type streamWriterStub struct {
	events []ValidatedStreamEvent
	fail   bool
}

func (writer *streamWriterStub) AppendStreamEvent(_ context.Context, event ValidatedStreamEvent) error {
	if writer.fail {
		writer.fail = false
		return errors.New("storage unavailable")
	}
	writer.events = append(writer.events, event)
	return nil
}

func TestStreamSessionPersistsExactLineageAndAssembledOutcome(t *testing.T) {
	binding, _ := SealBinding(context.Background(), validBinding())
	writer := &streamWriterStub{}
	session, err := NewStreamSession(context.Background(), binding, writer)
	if err != nil {
		t.Fatal(err)
	}
	started, err := session.Start(context.Background(), timestamp(5))
	if err != nil {
		t.Fatal(err)
	}
	sources := append([]string(nil), binding.OrderedSourceRecordIDs...)
	slices.Sort(sources)
	if started.Value().Sequence != 1 || !slices.Equal(started.Value().SourceRecordIDs, sources) {
		t.Fatalf("started=%#v", started.Value())
	}
	first, err := session.Append(context.Background(), "chunk", []byte("answer"), sources, timestamp(6))
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Append(context.Background(), "item", []byte(":evidence"), sources[:1], timestamp(7))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := session.Finish(context.Background(), "succeeded", timestamp(8))
	if err != nil {
		t.Fatal(err)
	}
	if first.Value().ChunkDigest != streamBytesDigest(streamChunkDigestDomain, []byte("answer")) ||
		second.Value().Sequence != 3 || terminal.Value().Sequence != 4 ||
		terminal.Value().AssembledDigest != streamBytesDigest(assembledDigestDomain, []byte("answer:evidence")) ||
		terminal.Value().Outcome != "succeeded" || len(writer.events) != 4 {
		t.Fatalf("first=%#v second=%#v terminal=%#v", first.Value(), second.Value(), terminal.Value())
	}
	if _, err := session.Append(context.Background(), "chunk", []byte("late"), sources, timestamp(9)); Reason(err) != "stream_state" {
		t.Fatalf("late err=%v", err)
	}
}

func TestStreamSessionMakesEveryTerminalOutcomeExplicit(t *testing.T) {
	for _, outcome := range []string{"succeeded", "empty", "interrupted", "canceled", "timeout", "failed", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			binding, _ := SealBinding(context.Background(), validBinding())
			writer := &streamWriterStub{}
			session, err := NewStreamSession(context.Background(), binding, writer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = session.Start(context.Background(), timestamp(5)); err != nil {
				t.Fatal(err)
			}
			if outcome != "empty" {
				sources := append([]string(nil), binding.OrderedSourceRecordIDs...)
				slices.Sort(sources)
				if _, err = session.Append(context.Background(), "chunk", []byte("partial"), sources, timestamp(6)); err != nil {
					t.Fatal(err)
				}
			}
			terminal, err := session.Finish(context.Background(), outcome, timestamp(7))
			if err != nil || terminal.Value().Outcome != outcome || terminal.Value().AssembledDigest == "" {
				t.Fatalf("terminal=%#v err=%v", terminal.Value(), err)
			}
		})
	}
}

func TestStreamSessionDeniesLineageDriftAndCommitsOnlyAfterDurableAppend(t *testing.T) {
	binding, _ := SealBinding(context.Background(), validBinding())
	writer := &streamWriterStub{fail: true}
	session, err := NewStreamSession(context.Background(), binding, writer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.Start(context.Background(), timestamp(5)); Code(err) != Unavailable {
		t.Fatalf("start err=%v", err)
	}
	started, err := session.Start(context.Background(), timestamp(5))
	if err != nil || started.Value().Sequence != 1 {
		t.Fatalf("retry=%#v err=%v", started.Value(), err)
	}
	if _, err = session.Append(context.Background(), "chunk", []byte("data"), []string{uuid(99)}, timestamp(6)); Reason(err) != "stream_lineage" {
		t.Fatalf("lineage err=%v", err)
	}
	if _, err = session.Finish(context.Background(), "succeeded", timestamp(7)); Reason(err) != "stream_outcome" {
		t.Fatalf("empty success err=%v", err)
	}
}

func TestFallbackRequiresFailedPrimaryAndExactInputLineage(t *testing.T) {
	primary, _ := SealBinding(context.Background(), validBinding())
	writer := &streamWriterStub{}
	session, _ := NewStreamSession(context.Background(), primary, writer)
	_, _ = session.Start(context.Background(), timestamp(5))
	terminal, err := session.Finish(context.Background(), "failed", timestamp(6))
	if err != nil {
		t.Fatal(err)
	}
	fallback := cloneBinding(primary)
	fallback.AttemptID = uuid(30)
	fallback.ProviderID = "llama_cpp.local"
	fallback.BindingDigest = ""
	fallback, err = SealBinding(context.Background(), fallback)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateFallbackLineage(context.Background(), terminal, primary, fallback); err != nil {
		t.Fatalf("fallback err=%v", err)
	}
	mutations := []func(*InferenceBinding){
		func(value *InferenceBinding) { value.SurfaceDigest = digest('f') },
		func(value *InferenceBinding) { value.OrderedSourceRecordIDs[0] = uuid(31) },
		func(value *InferenceBinding) { value.ProviderID = primary.ProviderID },
	}
	for index, mutate := range mutations {
		value := cloneBinding(fallback)
		mutate(&value)
		value.BindingDigest = ""
		value, _ = SealBinding(context.Background(), value)
		if err := ValidateFallbackLineage(context.Background(), terminal, primary, value); Reason(err) != "fallback_lineage" {
			t.Fatalf("mutation[%d] err=%v", index, err)
		}
	}
}
