package entityresolution

import (
	"context"
	"slices"
)

const (
	ConfidenceMethod                 = "coh.entity-confidence"
	ExactMatchWeight                 = int32(500_000)
	IndependentCorroborationWeight   = int32(150_000)
	MaximumIndependentCorroborations = 2
	AmbiguityPenalty                 = int32(-250_000)
)

var (
	sourceQualityWeights = map[string]int32{"unassessed": 0, "limited": 25_000, "standard": 50_000, "high": 100_000}
	recencyWeights       = map[string]int32{"unassessed": 0, "stale": 0, "recent": 50_000, "current": 100_000}
	counterWeights       = map[string]int32{
		"shared_identifier": -250_000, "conflicting_attribute": -300_000, "temporal_impossibility": -600_000,
		"explicit_separation": -1_000_000, "source_unreliability": -200_000, "stale_observation": -150_000,
		"analyst_rejection": -1_000_000,
	}
)

type ConfidenceEvidenceInput struct {
	Observation       Observation
	ObservationDigest string
	Link              EvidenceLink
	SourceQuality     string
	Recency           string
}

type ConfidenceInput struct {
	Evidence            []ConfidenceEvidenceInput
	Counterevidence     []Counterevidence
	MatchingEntityCount uint32
}

func ComposeConfidence(ctx context.Context, input ConfidenceInput) (Confidence, []byte, string, error) {
	if err := checkContext(ctx); err != nil {
		return Confidence{}, nil, "", err
	}
	if len(input.Evidence) == 0 || len(input.Evidence) > MaximumLookupObservations ||
		len(input.Counterevidence) > MaximumLookupEntities || input.MatchingEntityCount > MaximumLookupEntities {
		return Confidence{}, nil, "", newError(InvalidInputError, ConfidenceInvalid, nil)
	}
	evidence := append([]ConfidenceEvidenceInput(nil), input.Evidence...)
	slices.SortFunc(evidence, compareConfidenceEvidence)
	links := make([]EvidenceLink, 0, len(evidence))
	observationDigests := make([]string, 0, len(evidence))
	independenceGroups := make(map[string]struct{}, len(evidence))
	sourceFamilies := make(map[string]struct{}, len(evidence))
	seenObservations := make(map[string]struct{}, len(evidence))
	ceiling := uint32(1_000_000)
	qualityWeight, recencyWeight := int32(0), int32(0)
	for _, item := range evidence {
		if err := validateConfidenceEvidence(ctx, item); err != nil {
			return Confidence{}, nil, "", err
		}
		if _, duplicate := seenObservations[item.Observation.ObservationID]; duplicate {
			return Confidence{}, nil, "", newError(InvalidInputError, ConfidenceInvalid, nil)
		}
		seenObservations[item.Observation.ObservationID] = struct{}{}
		independenceGroups[item.Link.IndependenceGroupDigest] = struct{}{}
		sourceFamilies[item.Link.SourceFamilyDigest] = struct{}{}
		links = append(links, item.Link)
		observationDigests = append(observationDigests, item.ObservationDigest)
		ceiling = min(ceiling, item.Observation.ConfidenceCeilingMillionths)
		qualityWeight = max(qualityWeight, sourceQualityWeights[item.SourceQuality])
		recencyWeight = max(recencyWeight, recencyWeights[item.Recency])
	}

	counterevidence, counterWeight, counterDigests, err := normalizeCounterevidence(input.Counterevidence)
	if err != nil {
		return Confidence{}, nil, "", err
	}
	independentSources := independentEvidenceCount(evidence)
	corroborations := min(max(independentSources-1, 0), MaximumIndependentCorroborations)
	corroborationWeight := int32(corroborations) * IndependentCorroborationWeight
	ambiguityWeight := int32(0)
	if input.MatchingEntityCount > 1 {
		ambiguityWeight = AmbiguityPenalty
	}
	components := []ConfidenceComponent{
		confidenceComponent("01.exact-match", "exact_match", ExactMatchWeight, observationDigests,
			struct {
				Observations []string `json:"observations"`
			}{observationDigests}),
		confidenceComponent("02.independent-corroboration", "independent_corroboration", corroborationWeight, observationDigests,
			struct {
				Groups         int `json:"independence_groups"`
				SourceFamilies int `json:"source_families"`
				Counted        int `json:"counted_corroborations"`
			}{len(independenceGroups), len(sourceFamilies), corroborations}),
		confidenceComponent("03.source-quality", "source_quality", qualityWeight, observationDigests,
			assessmentBasis(evidence, true)),
		confidenceComponent("04.recency", "recency", recencyWeight, observationDigests,
			assessmentBasis(evidence, false)),
		confidenceComponent("05.counterevidence", "counterevidence", counterWeight, counterDigests,
			struct {
				RecordDigests []string `json:"record_digests"`
			}{counterRecordDigests(counterevidence)}),
		confidenceComponent("06.ambiguity", "ambiguity_penalty", ambiguityWeight, observationDigests,
			struct {
				MatchingEntities uint32 `json:"matching_entities"`
			}{input.MatchingEntityCount}),
	}
	total := int64(ExactMatchWeight) + int64(corroborationWeight) + int64(qualityWeight) + int64(recencyWeight) +
		int64(counterWeight) + int64(ambiguityWeight)
	preCeiling := uint32(min(max(total, int64(0)), int64(1_000_000)))
	final := min(preCeiling, ceiling)
	confidence := Confidence{Method: ConfidenceMethod, MethodVersion: MethodVersion, Components: components,
		SupportingEvidence: links, Counterevidence: counterevidence, PreCeilingMillionths: preCeiling,
		CeilingMillionths: ceiling, FinalMillionths: final, Label: confidenceLabel(final)}
	canonical, digest, canonicalErr := canonicalValue(confidence)
	if canonicalErr != nil {
		return Confidence{}, nil, "", canonicalErr
	}
	return confidence, canonical, digest, nil
}

func validateConfidenceEvidence(ctx context.Context, item ConfidenceEvidenceInput) error {
	_, digest, err := CanonicalObservation(ctx, item.Observation)
	if err != nil || digest != item.ObservationDigest || item.Observation.Validity != "current" ||
		item.Link.ObservationID != item.Observation.ObservationID || item.Link.ObservationDigest != item.ObservationDigest ||
		!validEvidenceLink(item.Link) || !validAssessment(item.SourceQuality, sourceQualityWeights) ||
		!validAssessment(item.Recency, recencyWeights) {
		return newError(InvalidInputError, ConfidenceInvalid, err)
	}
	_, bindingDigest, err := canonicalValue(item.Observation.Evidence)
	if err != nil || bindingDigest != item.Link.EvidenceBindingDigest {
		return newError(InvalidInputError, ConfidenceInvalid, err)
	}
	return nil
}

func normalizeCounterevidence(values []Counterevidence) ([]Counterevidence, int32, []string, error) {
	result := append([]Counterevidence(nil), values...)
	for index := range result {
		result[index].EvidenceLinks = append([]EvidenceLink(nil), result[index].EvidenceLinks...)
		slices.SortFunc(result[index].EvidenceLinks, compareEvidenceLink)
	}
	slices.SortFunc(result, func(left, right Counterevidence) int {
		if comparison := compareString(left.RecordDigest, right.RecordDigest); comparison != 0 {
			return comparison
		}
		return compareString(left.CounterevidenceID, right.CounterevidenceID)
	})
	seenIDs, seenDigests := make(map[string]struct{}, len(result)), make(map[string]struct{}, len(result))
	total := int64(0)
	observationSet := make(map[string]struct{})
	for _, item := range result {
		expectedWeight, reasonFound := counterWeights[item.Reason]
		expectedBlocking := slices.Contains([]string{"temporal_impossibility", "explicit_separation", "analyst_rejection"}, item.Reason)
		expectedDigest, err := CounterevidenceRecordDigest(item)
		if err != nil || !reasonFound || item.WeightMillionths != expectedWeight || item.BlocksMerge != expectedBlocking || expectedDigest != item.RecordDigest ||
			!uuidPattern.MatchString(item.CounterevidenceID) || len(item.EvidenceLinks) == 0 || len(item.EvidenceLinks) > 256 {
			return nil, 0, nil, newError(InvalidInputError, ConfidenceInvalid, err)
		}
		if _, duplicate := seenIDs[item.CounterevidenceID]; duplicate {
			return nil, 0, nil, newError(InvalidInputError, ConfidenceInvalid, nil)
		}
		if _, duplicate := seenDigests[item.RecordDigest]; duplicate {
			return nil, 0, nil, newError(InvalidInputError, ConfidenceInvalid, nil)
		}
		seenIDs[item.CounterevidenceID], seenDigests[item.RecordDigest] = struct{}{}, struct{}{}
		seenLinks := make(map[string]struct{}, len(item.EvidenceLinks))
		for index, link := range item.EvidenceLinks {
			if !validEvidenceLink(link) || index > 0 && compareEvidenceLink(item.EvidenceLinks[index-1], link) >= 0 {
				return nil, 0, nil, newError(InvalidInputError, ConfidenceInvalid, nil)
			}
			if _, duplicate := seenLinks[link.ObservationID]; duplicate {
				return nil, 0, nil, newError(InvalidInputError, ConfidenceInvalid, nil)
			}
			seenLinks[link.ObservationID] = struct{}{}
			observationSet[link.ObservationDigest] = struct{}{}
		}
		total += int64(item.WeightMillionths)
	}
	observationDigests := make([]string, 0, len(observationSet))
	for digest := range observationSet {
		observationDigests = append(observationDigests, digest)
	}
	slices.Sort(observationDigests)
	return result, int32(max(total, int64(-1_000_000))), observationDigests, nil
}

func CounterevidenceRecordDigest(value Counterevidence) (string, error) {
	links := append([]EvidenceLink(nil), value.EvidenceLinks...)
	slices.SortFunc(links, compareEvidenceLink)
	_, digest, err := canonicalValue(struct {
		CounterevidenceID string         `json:"counterevidence_id"`
		Reason            string         `json:"reason"`
		EvidenceLinks     []EvidenceLink `json:"evidence_links"`
		WeightMillionths  int32          `json:"weight_millionths"`
		BlocksMerge       bool           `json:"blocks_merge"`
	}{value.CounterevidenceID, value.Reason, links, value.WeightMillionths, value.BlocksMerge})
	return digest, err
}

func confidenceComponent(id, kind string, value int32, observations []string, basis any) ConfidenceComponent {
	_, basisDigest, _ := canonicalValue(basis)
	return ConfidenceComponent{ComponentID: id, Kind: kind, ValueMillionths: value,
		ObservationDigests: append([]string(nil), observations...), BasisDigest: basisDigest}
}

type assessmentRecord struct {
	ObservationDigest string `json:"observation_digest"`
	Assessment        string `json:"assessment"`
}

func assessmentBasis(evidence []ConfidenceEvidenceInput, quality bool) []assessmentRecord {
	result := make([]assessmentRecord, 0, len(evidence))
	for _, item := range evidence {
		assessment := item.Recency
		if quality {
			assessment = item.SourceQuality
		}
		result = append(result, assessmentRecord{item.ObservationDigest, assessment})
	}
	return result
}

func counterRecordDigests(values []Counterevidence) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.RecordDigest)
	}
	return result
}

func validEvidenceLink(value EvidenceLink) bool {
	return uuidPattern.MatchString(value.ObservationID) && digestPattern.MatchString(value.ObservationDigest) &&
		digestPattern.MatchString(value.EvidenceBindingDigest) && digestPattern.MatchString(value.SourceFamilyDigest) &&
		digestPattern.MatchString(value.IndependenceGroupDigest)
}

func validAssessment(value string, weights map[string]int32) bool {
	_, exists := weights[value]
	return exists
}

func compareConfidenceEvidence(left, right ConfidenceEvidenceInput) int {
	if comparison := compareString(left.ObservationDigest, right.ObservationDigest); comparison != 0 {
		return comparison
	}
	return compareString(left.Observation.ObservationID, right.Observation.ObservationID)
}

func compareEvidenceLink(left, right EvidenceLink) int {
	if comparison := compareString(left.ObservationDigest, right.ObservationDigest); comparison != 0 {
		return comparison
	}
	return compareString(left.ObservationID, right.ObservationID)
}

func independentEvidenceCount(evidence []ConfidenceEvidenceInput) int {
	adjacency := make(map[string]map[string]struct{}, len(evidence))
	for _, item := range evidence {
		groups := adjacency[item.Link.SourceFamilyDigest]
		if groups == nil {
			groups = make(map[string]struct{})
			adjacency[item.Link.SourceFamilyDigest] = groups
		}
		groups[item.Link.IndependenceGroupDigest] = struct{}{}
	}
	sources := make([]string, 0, len(adjacency))
	for source := range adjacency {
		sources = append(sources, source)
	}
	slices.Sort(sources)
	matchedGroup := make(map[string]string)
	var augment func(string, map[string]bool) bool
	augment = func(source string, visited map[string]bool) bool {
		groups := make([]string, 0, len(adjacency[source]))
		for group := range adjacency[source] {
			groups = append(groups, group)
		}
		slices.Sort(groups)
		for _, group := range groups {
			if visited[group] {
				continue
			}
			visited[group] = true
			previous, occupied := matchedGroup[group]
			if !occupied || augment(previous, visited) {
				matchedGroup[group] = source
				return true
			}
		}
		return false
	}
	count := 0
	for _, source := range sources {
		if augment(source, make(map[string]bool)) {
			count++
		}
	}
	return count
}

func confidenceLabel(value uint32) string {
	switch {
	case value < 250_000:
		return "very_low"
	case value < 500_000:
		return "low"
	case value < 750_000:
		return "medium"
	case value < 900_000:
		return "high"
	default:
		return "very_high"
	}
}
