package investigationprojection

import (
	"bytes"
	"context"
	"slices"
	"testing"
)

func TestEVAL017UncertaintyCorpusSurvivesEveryProjection(t *testing.T) {
	facts := uncertaintyCorpus(t)
	states := make(map[Kind]*ReductionState)
	for _, kind := range []Kind{Correlation, Hypothesis, Timeline} {
		reducer, _ := NewReducer(kind)
		var state *ReductionState
		var err error
		for _, fact := range facts {
			state, err = reducer.Reduce(context.Background(), state, fact, fixtureStateVersion())
			if err != nil {
				t.Fatalf("kind=%s sequence=%d err=%v", kind, fact.Sequence, err)
			}
		}
		states[kind] = state
		if state.Watermark.Sequence != uint64(len(facts)) || state.Value.Completeness.Status != "partial" ||
			len(state.Value.Completeness.NegativeEvidenceDigests) != 1 || len(state.Value.Completeness.GapDigests) != 1 ||
			len(state.Value.Completeness.ConflictDigests) != 1 {
			t.Fatalf("kind=%s state=%+v", kind, state)
		}
		claim := state.Value.Claims[0]
		if len(claim.SupportingEvidenceDigests) != 1 || len(claim.CounterevidenceDigests) != 1 || len(claim.Unknowns) != 4 {
			t.Fatalf("kind=%s claim=%+v", kind, claim)
		}
	}
	if hypothesis := states[Hypothesis].Value.Hypotheses; len(hypothesis) != 1 || hypothesis[0].Disposition != "inconclusive" ||
		len(hypothesis[0].Unknowns) != 2 {
		t.Fatalf("hypotheses=%+v", hypothesis)
	}
	timeline := states[Timeline].Value.Timeline
	if len(timeline) != 1 || timeline[0].RelationToPrevious != "uncertain" || timeline[0].TimeRef.Precision != "unknown" ||
		timeline[0].OrderConfidenceMillionths != 200_000 || timeline[0].DuplicateOf == nil ||
		*timeline[0].DuplicateOf != "entry-original" || len(timeline[0].GapDigests) != 1 ||
		len(timeline[0].ConflictDigests) != 1 || len(timeline[0].Unknowns) != 4 {
		t.Fatalf("timeline=%+v", timeline)
	}
}

func TestEVAL017CorpusRebuildIsByteIdentical(t *testing.T) {
	facts := uncertaintyCorpus(t)
	var expected []byte
	for iteration := 0; iteration < 2; iteration++ {
		reducer, _ := NewReducer(Timeline)
		var state *ReductionState
		for _, fact := range facts {
			var err error
			state, err = reducer.Reduce(context.Background(), state, fact, fixtureStateVersion())
			if err != nil {
				t.Fatal(err)
			}
		}
		projection, _, err := buildRecords(context.Background(), state, EvidenceDigests{
			AuditDigest: projectionDigest("eval-audit"), ProvenanceDigest: projectionDigest("eval-provenance")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, err := CanonicalProjection(context.Background(), projection)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			expected = canonical
		} else if !bytes.Equal(expected, canonical) {
			t.Fatal("same facts and versions produced different canonical projection bytes")
		}
	}
}

func uncertaintyCorpus(t *testing.T) []Fact {
	t.Helper()
	unknowns := []Unknown{
		{Code: "clock_skew", BasisDigest: projectionDigest("dst-clock-skew")},
		{Code: "low_precision", BasisDigest: projectionDigest("low-precision")},
		{Code: "missing_timezone", BasisDigest: projectionDigest("missing-timezone")},
		{Code: "source_conflict", BasisDigest: projectionDigest("source-conflict")},
	}
	queried := []string{projectionDigest("source-a"), projectionDigest("source-b")}
	slices.Sort(queried)
	partial := Completeness{Status: "partial", QueriedSourceDigests: queried,
		CompletedSourceDigests: []string{queried[0]}, GapDigests: []string{projectionDigest("coverage-gap")},
		NegativeEvidenceDigests: []string{projectionDigest("bounded-negative-result")},
		ConflictDigests:         []string{projectionDigest("source-conflict-record")}}
	first := validProjectionFact(t, 1, nil, "claim")
	first.SupportingEvidenceDigests = []string{projectionDigest("support")}
	first.CounterevidenceDigests = []string{projectionDigest("counter")}
	first.Unknowns, first.Completeness = unknowns, partial
	_, head, _ := CanonicalFact(context.Background(), first)
	previousFirst := head
	second := validProjectionFact(t, 2, &previousFirst, "time_order")
	relation, order, duplicate := "uncertain", uint32(200_000), "entry-original"
	second.TimeRelation, second.OrderConfidenceMillionths, second.DuplicateOf = &relation, &order, &duplicate
	second.TimeRefs[0].Precision = "unknown"
	second.Binding.TimeRefs = cloneSlice(second.TimeRefs)
	second.GapDigests = []string{projectionDigest("timeline-gap")}
	second.ConflictDigests = []string{projectionDigest("timeline-conflict")}
	second.Unknowns, second.Completeness = cloneSlice(unknowns), partial
	_, head, _ = CanonicalFact(context.Background(), second)
	previousSecond := head
	third := validProjectionFact(t, 3, &previousSecond, "hypothesis_disposition")
	disposition := "inconclusive"
	third.HypothesisDisposition = &disposition
	third.Unknowns = cloneSlice(unknowns[:2])
	third.Completeness = partial
	_, head, _ = CanonicalFact(context.Background(), third)
	previousThird := head
	fourth := validProjectionFact(t, 4, &previousThird, "completeness")
	fourth.Completeness = partial
	return []Fact{first, second, third, fourth}
}
