package entityresolution

import (
	"context"
	"math"
	"slices"
	"strconv"
)

// EntityRevisionCore is the non-cyclic identity of an immutable entity
// revision. EntityRef.RecordDigest hashes this record; decision, history,
// audit, and provenance bindings are layered onto the full Entity afterward.
type EntityRevisionCore struct {
	SchemaVersion      string           `json:"schema_version"`
	ContractVersion    string           `json:"contract_version"`
	MethodVersion      string           `json:"method_version"`
	EntityID           string           `json:"entity_id"`
	Revision           uint64           `json:"revision"`
	Scope              Scope            `json:"scope"`
	Status             string           `json:"status"`
	Classification     string           `json:"classification"`
	MemberObservations []ObservationRef `json:"member_observations"`
	AliasProofs        []AliasProof     `json:"alias_proofs"`
	Confidence         Confidence       `json:"confidence"`
	CreatedAt          string           `json:"created_at"`
	UpdatedAt          string           `json:"updated_at"`
}

func EntityRecordDigest(ctx context.Context, entity Entity) ([]byte, string, error) {
	if err := validateEntityCore(ctx, entityCore(entity)); err != nil {
		return nil, "", err
	}
	return canonicalValue(entityCore(entity))
}

func ValidateEntityRevision(ctx context.Context, entity Entity, reference EntityRef) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	_, digest, err := EntityRecordDigest(ctx, entity)
	if err != nil {
		return err
	}
	if !validEntityRef(reference) || entity.EntityID != reference.EntityID || entity.Revision != reference.Revision ||
		digest != reference.RecordDigest || !digestPattern.MatchString(entity.CreationDecisionDigest) ||
		!digestPattern.MatchString(entity.HistoryHeadDigest) || !digestPattern.MatchString(entity.AuditDigest) ||
		!digestPattern.MatchString(entity.ProvenanceDigest) || entity.PreviousProvenanceDigest != nil &&
		!digestPattern.MatchString(*entity.PreviousProvenanceDigest) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func entityCore(value Entity) EntityRevisionCore {
	return EntityRevisionCore{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		MethodVersion: value.MethodVersion, EntityID: value.EntityID, Revision: value.Revision, Scope: value.Scope,
		Status: value.Status, Classification: value.Classification,
		MemberObservations: append([]ObservationRef(nil), value.MemberObservations...),
		AliasProofs:        append([]AliasProof(nil), value.AliasProofs...), Confidence: value.Confidence,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func validateEntityCore(ctx context.Context, value EntityRevisionCore) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != EntitySchemaVersion || value.ContractVersion != ContractVersion || value.MethodVersion != MethodVersion ||
		!uuidPattern.MatchString(value.EntityID) || value.Revision == 0 || value.Revision > math.MaxInt64 || !validScope(value.Scope) ||
		!slices.Contains([]string{"active", "superseded"}, value.Status) || !validClassification(value.Classification) ||
		len(value.MemberObservations) == 0 || len(value.MemberObservations) > MaximumLookupObservations ||
		len(value.AliasProofs) > MaximumLookupEntities || !validTimestamp(value.CreatedAt) || !validTimestamp(value.UpdatedAt) ||
		value.CreatedAt > value.UpdatedAt || !validConfidenceRecord(value.Confidence) ||
		!confidenceBoundToMembers(value.Confidence, value.MemberObservations) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	for index, member := range value.MemberObservations {
		if !validObservationRef(member) || index > 0 && compareObservationRef(value.MemberObservations[index-1], member) >= 0 {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
	}
	if !validAliasProofs(value.AliasProofs) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func validConfidenceRecord(value Confidence) bool {
	if value.Method != ConfidenceMethod || value.MethodVersion != MethodVersion || len(value.Components) != 6 ||
		value.PreCeilingMillionths > 1_000_000 || value.CeilingMillionths > 1_000_000 || value.FinalMillionths > 1_000_000 ||
		value.FinalMillionths != min(value.PreCeilingMillionths, value.CeilingMillionths) ||
		value.Label != confidenceLabel(value.FinalMillionths) || len(value.SupportingEvidence) == 0 ||
		len(value.SupportingEvidence) > MaximumLookupObservations || len(value.Counterevidence) > MaximumLookupEntities {
		return false
	}
	expectedIDs := []string{"01.exact-match", "02.independent-corroboration", "03.source-quality", "04.recency", "05.counterevidence", "06.ambiguity"}
	expectedKinds := []string{"exact_match", "independent_corroboration", "source_quality", "recency", "counterevidence", "ambiguity_penalty"}
	allowedWeights := [][]int32{{ExactMatchWeight}, {0, 150_000, 300_000}, {0, 25_000, 50_000, 100_000},
		{0, 50_000, 100_000}, {}, {0, AmbiguityPenalty}}
	supportDigests := make([]string, 0, len(value.SupportingEvidence))
	for index, link := range value.SupportingEvidence {
		if !validEvidenceLink(link) || index > 0 && compareEvidenceLink(value.SupportingEvidence[index-1], link) >= 0 {
			return false
		}
		supportDigests = append(supportDigests, link.ObservationDigest)
	}
	normalizedCounter, counterWeight, counterObservationDigests, err := normalizeCounterevidence(value.Counterevidence)
	if err != nil || !sameCanonicalValue(normalizedCounter, value.Counterevidence) {
		return false
	}
	allowedWeights[4] = []int32{counterWeight}
	total := int64(0)
	for index, component := range value.Components {
		if component.ComponentID != expectedIDs[index] || component.Kind != expectedKinds[index] ||
			!slices.Contains(allowedWeights[index], component.ValueMillionths) || !digestPattern.MatchString(component.BasisDigest) ||
			!validDigestSet(component.ObservationDigests) {
			return false
		}
		expectedDigests := supportDigests
		if index == 4 {
			expectedDigests = counterObservationDigests
		}
		if !slices.Equal(component.ObservationDigests, expectedDigests) {
			return false
		}
		total += int64(component.ValueMillionths)
	}
	return value.PreCeilingMillionths == uint32(min(max(total, int64(0)), int64(1_000_000)))
}

func validAliasProofs(values []AliasProof) bool {
	edges := make(map[string]string, len(values))
	for index, value := range values {
		if !validAliasProof(value) || index > 0 && compareAliasProof(values[index-1], value) >= 0 {
			return false
		}
		from := aliasNode(value.IdentifierType, value.FromMatchDigest, value.FromKeyRevision)
		to := aliasNode(value.IdentifierType, value.ToMatchDigest, value.ToKeyRevision)
		if from == to {
			return false
		}
		if existing, duplicate := edges[from]; duplicate && existing != to {
			return false
		}
		edges[from] = to
	}
	for start := range edges {
		seen := make(map[string]bool)
		for node := start; node != ""; node = edges[node] {
			if seen[node] {
				return false
			}
			seen[node] = true
		}
	}
	return true
}

func validAliasProof(value AliasProof) bool {
	if !slices.Contains([]string{"hostname", "username", "ipv4", "ipv6", "process_id", "sha256", "cloud_resource_id"}, value.IdentifierType) ||
		!digestPattern.MatchString(value.FromMatchDigest) || !digestPattern.MatchString(value.ToMatchDigest) ||
		value.FromKeyRevision == 0 || value.FromKeyRevision > math.MaxInt64 || value.ToKeyRevision == 0 ||
		value.ToKeyRevision > math.MaxInt64 || !digestPattern.MatchString(value.VerifierDecisionDigest) ||
		len(value.EvidenceLinkDigests) == 0 || len(value.EvidenceLinkDigests) > 256 || !validTimestamp(value.CreatedAt) {
		return false
	}
	return validDigestSet(value.EvidenceLinkDigests)
}

func validDigestSet(values []string) bool {
	for index, value := range values {
		if !digestPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validObservationRef(value ObservationRef) bool {
	return uuidPattern.MatchString(value.ObservationID) && digestPattern.MatchString(value.ObservationDigest)
}

func compareObservationRef(left, right ObservationRef) int {
	if comparison := compareString(left.ObservationDigest, right.ObservationDigest); comparison != 0 {
		return comparison
	}
	return compareString(left.ObservationID, right.ObservationID)
}

func compareAliasProof(left, right AliasProof) int {
	leftKey := aliasNode(left.IdentifierType, left.FromMatchDigest, left.FromKeyRevision) + aliasNode(left.IdentifierType, left.ToMatchDigest, left.ToKeyRevision)
	rightKey := aliasNode(right.IdentifierType, right.FromMatchDigest, right.FromKeyRevision) + aliasNode(right.IdentifierType, right.ToMatchDigest, right.ToKeyRevision)
	return compareString(leftKey, rightKey)
}

func aliasNode(identifierType, digest string, revision uint64) string {
	return identifierType + ":" + digest + ":" + strconv.FormatUint(revision, 10)
}

func sameCanonicalValue(left, right any) bool {
	_, leftDigest, leftErr := canonicalValue(left)
	_, rightDigest, rightErr := canonicalValue(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
}
