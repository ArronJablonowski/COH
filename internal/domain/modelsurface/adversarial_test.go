package modelsurface

import (
	"bytes"
	"context"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func TestEverySingleByteRecordMutationFailsOrChangesIdentity(t *testing.T) {
	tests := []struct {
		fixture string
		decode  func([]byte) ([]byte, string, error)
	}{
		{"event-vocabulary.valid.json", decodeVocabularyTest}, {"source.valid.json", decodeSourceTest},
		{"projection.valid.json", decodeProjectionTest}, {"binding.valid.json", decodeBindingTest},
		{"stream.valid.json", decodeStreamTest}, {"compaction.valid.json", decodeCompactionTest},
		{"transition.valid.json", decodeTransitionTest},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			original, err := os.ReadFile("../../../contracts/model-surface/v1/fixtures/" + test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			original = bytes.TrimSuffix(original, []byte{'\n'})
			_, originalDigest, err := test.decode(original)
			if err != nil {
				t.Fatal(err)
			}
			for index := range original {
				mutated := append([]byte(nil), original...)
				mutated[index] ^= 1
				canonical, digest, decodeErr := test.decode(mutated)
				if decodeErr == nil && (digest == originalDigest || slices.Equal(canonical, original)) {
					t.Fatalf("mutation[%d] retained identity", index)
				}
			}
		})
	}
}

func TestConcurrentStreamAppendProducesOneContiguousDurableSequence(t *testing.T) {
	binding, _ := SealBinding(context.Background(), validBinding())
	writer := &streamWriterStub{}
	session, _ := NewStreamSession(context.Background(), binding, writer)
	if _, err := session.Start(context.Background(), timestamp(5)); err != nil {
		t.Fatal(err)
	}
	sources := append([]string(nil), binding.OrderedSourceRecordIDs...)
	slices.Sort(sources)
	const workers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := session.Append(context.Background(), "chunk", []byte("x"), sources, timestamp(6))
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	terminal, err := session.Finish(context.Background(), "succeeded", timestamp(7))
	if err != nil || terminal.Value().Sequence != workers+2 || len(writer.events) != workers+2 {
		t.Fatalf("terminal=%#v events=%d err=%v", terminal.Value(), len(writer.events), err)
	}
	for index, event := range writer.events {
		if event.Value().Sequence != uint64(index+1) {
			t.Fatalf("event[%d]=%d", index, event.Value().Sequence)
		}
	}
}

func TestConcurrentRecoveryCASAllowsExactlyOneAdvance(t *testing.T) {
	controller, _, _, prepared, binding := newRecoveryFixture(t)
	current, _, err := controller.Prepare(context.Background(), "cas.recovery", prepared)
	if err != nil {
		t.Fatal(err)
	}
	var allowed atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, advanceErr := controller.Advance(context.Background(), "cas.recovery", current, AdvanceTransition{TransitionID: uuid(100 + index), Phase: "verified", BindingDigest: binding.BindingDigest, UpdatedAt: timestamp(4)})
			if advanceErr == nil {
				allowed.Add(1)
			} else if Reason(advanceErr) != "transition_conflict" {
				t.Errorf("advance err=%v", advanceErr)
			}
		}(index)
	}
	wait.Wait()
	if allowed.Load() != 1 {
		t.Fatalf("allowed=%d", allowed.Load())
	}
}

func TestCancellationNeverCommitsStreamOrRecoveryState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	binding, _ := SealBinding(context.Background(), validBinding())
	writer := &streamWriterStub{}
	session, _ := NewStreamSession(context.Background(), binding, writer)
	if _, err := session.Start(ctx, timestamp(5)); Code(err) != Canceled || len(writer.events) != 0 {
		t.Fatalf("stream err=%v events=%d", err, len(writer.events))
	}
	controller, store, _, prepared, _ := newRecoveryFixture(t)
	if _, _, err := controller.Prepare(ctx, "cancel.recovery", prepared); Code(err) != Canceled || len(store.latest) != 0 {
		t.Fatalf("recovery err=%v latest=%d", err, len(store.latest))
	}
}

func TestCompactionPressureOverMaximumCoverageDeniesBeforeReads(t *testing.T) {
	compactor, projection, request := newCompactionFixture(t)
	request.CoveredSourceRecordIDs = make([]string, MaximumItems+1)
	for index := range request.CoveredSourceRecordIDs {
		request.CoveredSourceRecordIDs[index] = uuid(1000 + index)
	}
	if _, err := compactor.Build(context.Background(), projection, request); Reason(err) != "compaction_request" {
		t.Fatalf("err=%v", err)
	}
}

func FuzzModelSurfaceStrictDecoders(f *testing.F) {
	f.Add(uint8(0), []byte(`{}`))
	fixtures := []string{"event-vocabulary.valid.json", "source.valid.json", "projection.valid.json", "binding.valid.json", "stream.valid.json", "compaction.valid.json", "transition.valid.json", "payload.valid.json"}
	for selector, name := range fixtures {
		value, err := os.ReadFile("../../../contracts/model-surface/v1/fixtures/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(selector), value)
	}
	f.Fuzz(func(t *testing.T, selector uint8, input []byte) {
		switch selector % 8 {
		case 0:
			_, _ = DecodeVocabulary(context.Background(), input)
		case 1:
			_, _ = DecodeSource(context.Background(), input)
		case 2:
			_, _ = DecodeProjection(context.Background(), input)
		case 3:
			_, _ = DecodeBinding(context.Background(), input)
		case 4:
			_, _ = DecodeStreamEvent(context.Background(), input)
		case 5:
			_, _ = DecodeCompaction(context.Background(), input)
		case 6:
			_, _ = DecodeTransition(context.Background(), input)
		case 7:
			_, _ = DecodePayload(context.Background(), input)
		}
	})
}
