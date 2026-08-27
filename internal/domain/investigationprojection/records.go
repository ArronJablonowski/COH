package investigationprojection

import "context"

func buildRecords(ctx context.Context, state *ReductionState, evidence EvidenceDigests, previousCheckpointDigest *string) (Projection, Checkpoint, error) {
	if state == nil || state.Value == nil || !digestPattern.MatchString(evidence.AuditDigest) ||
		!digestPattern.MatchString(evidence.ProvenanceDigest) {
		return Projection{}, Checkpoint{}, newError(InvalidInputError, InvalidInput, nil)
	}
	seed := state.FactSetDigest + ":" + string(state.Value.Kind) + ":" + state.StateVersion.AuthoritativeStateDigest
	projection := Projection{SchemaVersion: ProjectionSchemaVersion, ContractVersion: ContractVersion,
		ReducerVersion: ReducerVersion, ProjectionID: deterministicUUID("projection:" + seed), Scope: state.Scope,
		Kind: state.Value.Kind, StateVersion: state.StateVersion, Watermark: state.Watermark, FactCount: state.FactCount,
		FactSetDigest: state.FactSetDigest, Claims: cloneClaims(state.Value.Claims),
		Hypotheses: cloneHypotheses(state.Value.Hypotheses), Timeline: cloneTimeline(state.Value.Timeline),
		Completeness: cloneCompleteness(state.Value.Completeness), AuditDigest: evidence.AuditDigest,
		ProvenanceDigest: evidence.ProvenanceDigest, CreatedAt: state.Watermark.CommittedAt}
	_, projectionDigest, err := calculateProjectionDigest(projection)
	if err != nil {
		return Projection{}, Checkpoint{}, err
	}
	projection.ProjectionDigest = projectionDigest
	if _, _, err := CanonicalProjection(ctx, projection); err != nil {
		return Projection{}, Checkpoint{}, err
	}
	checkpoint := Checkpoint{SchemaVersion: CheckpointSchemaVersion, ContractVersion: ContractVersion,
		CheckpointID: deterministicUUID("checkpoint:" + seed), Scope: state.Scope, Kind: state.Value.Kind,
		StateVersion: state.StateVersion, Watermark: state.Watermark, FactSetDigest: state.FactSetDigest,
		ProjectionDigest: projection.ProjectionDigest, PreviousCheckpointDigest: cloneString(previousCheckpointDigest),
		AuditDigest: evidence.AuditDigest, ProvenanceDigest: evidence.ProvenanceDigest, CreatedAt: state.Watermark.CommittedAt}
	_, checkpointDigest, err := calculateCheckpointDigest(checkpoint)
	if err != nil {
		return Projection{}, Checkpoint{}, err
	}
	checkpoint.CheckpointDigest = checkpointDigest
	if _, _, err := CanonicalCheckpoint(ctx, checkpoint); err != nil {
		return Projection{}, Checkpoint{}, err
	}
	return projection, checkpoint, nil
}

func verifiedReductionState(ctx context.Context, projection Projection, checkpoint Checkpoint) (*ReductionState, error) {
	if _, _, err := CanonicalProjection(ctx, projection); err != nil {
		return nil, newError(ConflictError, IntegrityFailure, err)
	}
	if _, _, err := CanonicalCheckpoint(ctx, checkpoint); err != nil {
		return nil, newError(ConflictError, IntegrityFailure, err)
	}
	_, calculatedProjection, err := calculateProjectionDigest(projection)
	if err != nil || calculatedProjection != projection.ProjectionDigest {
		return nil, newError(ConflictError, IntegrityFailure, err)
	}
	_, calculatedCheckpoint, err := calculateCheckpointDigest(checkpoint)
	if err != nil || calculatedCheckpoint != checkpoint.CheckpointDigest || checkpoint.Scope != projection.Scope ||
		checkpoint.Kind != projection.Kind || checkpoint.StateVersion != projection.StateVersion ||
		!sameWatermark(checkpoint.Watermark, projection.Watermark) || checkpoint.FactSetDigest != projection.FactSetDigest ||
		checkpoint.ProjectionDigest != projection.ProjectionDigest || checkpoint.AuditDigest != projection.AuditDigest ||
		checkpoint.ProvenanceDigest != projection.ProvenanceDigest {
		return nil, newError(ConflictError, IntegrityFailure, err)
	}
	value := &Value{Kind: projection.Kind, Claims: cloneClaims(projection.Claims), Hypotheses: cloneHypotheses(projection.Hypotheses),
		Timeline: cloneTimeline(projection.Timeline), Completeness: cloneCompleteness(projection.Completeness)}
	return &ReductionState{Scope: projection.Scope, StateVersion: projection.StateVersion, Watermark: projection.Watermark,
		FactCount: projection.FactCount, FactSetDigest: projection.FactSetDigest, Value: value}, nil
}

func calculateProjectionDigest(value Projection) ([]byte, string, error) {
	value.ProjectionDigest = ""
	return canonicalValue(value)
}

func calculateCheckpointDigest(value Checkpoint) ([]byte, string, error) {
	value.CheckpointDigest = ""
	return canonicalValue(value)
}

func cloneClaims(values []Claim) []Claim {
	result := cloneSlice(values)
	for index := range result {
		result[index].SupportingEvidenceDigests = cloneSlice(result[index].SupportingEvidenceDigests)
		result[index].CounterevidenceDigests = cloneSlice(result[index].CounterevidenceDigests)
		result[index].Unknowns = cloneSlice(result[index].Unknowns)
		result[index].EntityRefs = cloneSlice(result[index].EntityRefs)
		result[index].Completeness = cloneCompleteness(result[index].Completeness)
	}
	return result
}

func cloneHypotheses(values []HypothesisValue) []HypothesisValue {
	result := cloneSlice(values)
	for index := range result {
		result[index].ClaimIDs = cloneSlice(result[index].ClaimIDs)
		result[index].SupportingEvidenceDigests = cloneSlice(result[index].SupportingEvidenceDigests)
		result[index].CounterevidenceDigests = cloneSlice(result[index].CounterevidenceDigests)
		result[index].Unknowns = cloneSlice(result[index].Unknowns)
		result[index].Completeness = cloneCompleteness(result[index].Completeness)
	}
	return result
}

func cloneTimeline(values []TimelineEntry) []TimelineEntry {
	result := cloneSlice(values)
	for index := range result {
		result[index].ClaimIDs = cloneSlice(result[index].ClaimIDs)
		result[index].EntityRefs = cloneSlice(result[index].EntityRefs)
		result[index].TimeRef = cloneTimeRef(result[index].TimeRef)
		result[index].DuplicateOf = cloneString(result[index].DuplicateOf)
		result[index].GapDigests = cloneSlice(result[index].GapDigests)
		result[index].ConflictDigests = cloneSlice(result[index].ConflictDigests)
		result[index].Unknowns = cloneSlice(result[index].Unknowns)
	}
	return result
}

func cloneProjection(value Projection) Projection {
	value.Watermark.HeadFactDigest = cloneString(value.Watermark.HeadFactDigest)
	value.Claims = cloneClaims(value.Claims)
	value.Hypotheses = cloneHypotheses(value.Hypotheses)
	value.Timeline = cloneTimeline(value.Timeline)
	value.Completeness = cloneCompleteness(value.Completeness)
	return value
}
