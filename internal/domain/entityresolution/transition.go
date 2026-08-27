package entityresolution

import (
	"context"
	"math"
	"slices"
)

type TransitionMetadata struct {
	DecisionID            string
	HistoryID             string
	HistorySequence       uint64
	OperationID           string
	Scope                 Scope
	ActorID               string
	ActorRevision         uint64
	CommandDigest         string
	Reason                string
	SupportingEvidence    []EvidenceLink
	Counterevidence       []Counterevidence
	Confidence            Confidence
	CreatedAt             string
	Deadline              string
	ReversesHistoryDigest *string
}

type EntityRevisionDraft struct {
	Entity    Entity
	Reference EntityRef
}

type TransitionPlan struct {
	Operation                   Operation
	Superseded                  []EntityRevisionDraft
	Outputs                     []EntityRevisionDraft
	Decision                    Decision
	DecisionCanonical           []byte
	DecisionDigest              string
	History                     History
	HistoryCanonical            []byte
	HistoryDigest               string
	AuthorizationDecisionDigest string
}

func validateTransitionMetadata(value TransitionMetadata) error {
	if !uuidPattern.MatchString(value.DecisionID) || !uuidPattern.MatchString(value.HistoryID) ||
		!uuidPattern.MatchString(value.OperationID) || !validScope(value.Scope) || !uuidPattern.MatchString(value.ActorID) ||
		value.ActorRevision == 0 || value.ActorRevision > math.MaxInt64 || !digestPattern.MatchString(value.CommandDigest) ||
		value.HistorySequence == 0 || value.HistorySequence > math.MaxInt64 || !validTimestamp(value.CreatedAt) ||
		!validTimestamp(value.Deadline) || value.CreatedAt > value.Deadline || !validConfidenceRecord(value.Confidence) ||
		!sameCanonicalValue(value.SupportingEvidence, value.Confidence.SupportingEvidence) ||
		!sameCanonicalValue(value.Counterevidence, value.Confidence.Counterevidence) ||
		value.ReversesHistoryDigest != nil && !digestPattern.MatchString(*value.ReversesHistoryDigest) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func loadCurrentInputs(ctx context.Context, store EntityStore, scope Scope, references []EntityRef, minimum int) ([]Entity, []EntityRef, error) {
	if nilDependency(store) {
		return nil, nil, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	if len(references) < minimum || len(references) > MaximumLookupEntities {
		return nil, nil, newError(InvalidInputError, TransitionInvalid, nil)
	}
	ordered := cloneSlice(references)
	slices.SortFunc(ordered, compareEntityRef)
	entities := make([]Entity, 0, len(ordered))
	for index, reference := range ordered {
		if !validEntityRef(reference) || index > 0 && ordered[index-1].EntityID == reference.EntityID {
			return nil, nil, newError(InvalidInputError, TransitionInvalid, nil)
		}
		entity, currentReference, found, err := store.LoadCurrentEntity(ctx, scope, reference.EntityID)
		if err = dependencyError(ctx, err); err != nil {
			return nil, nil, err
		}
		if !found || currentReference != reference {
			return nil, nil, newError(ConflictError, RevisionConflict, nil)
		}
		if entity.Scope != scope {
			return nil, nil, newError(DeniedError, ScopeMismatch, nil)
		}
		if err := ValidateEntityRevision(ctx, entity, reference); err != nil {
			return nil, nil, newError(InvalidInputError, TransitionInvalid, err)
		}
		if entity.Status != "active" {
			return nil, nil, newError(ConflictError, RevisionConflict, nil)
		}
		entities = append(entities, entity)
	}
	return entities, ordered, nil
}

func verifyTransitionAuthorization(ctx context.Context, verifier AuthorizationVerifier, operation Operation,
	metadata TransitionMetadata, inputs []EntityRef) (string, error) {
	if nilDependency(verifier) {
		return "", newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	decision, err := verifier.VerifyAuthorization(ctx, AuthorizationRequest{Operation: operation, OperationID: metadata.OperationID,
		Scope: metadata.Scope, ActorID: metadata.ActorID, ActorRevision: metadata.ActorRevision,
		CommandDigest: metadata.CommandDigest, InputEntities: cloneSlice(inputs), Deadline: metadata.Deadline})
	if err = dependencyError(ctx, err); err != nil {
		return "", err
	}
	if !decision.Allowed || decision.ActorRevision != metadata.ActorRevision || decision.CaseRevision == 0 ||
		decision.CaseRevision > math.MaxInt64 || !digestPattern.MatchString(decision.DecisionDigest) ||
		!digestPattern.MatchString(decision.RevocationDigest) || !validTimestamp(decision.ExpiresAt) ||
		decision.ExpiresAt < metadata.Deadline {
		return "", newError(DeniedError, AuthorizationDenied, nil)
	}
	return decision.DecisionDigest, nil
}

func finalizeTransition(metadata TransitionMetadata, operation Operation, inputs []EntityRef, outputs, superseded []EntityRevisionDraft,
	partitions []Partition, parents []string, authorizationDigest string) (TransitionPlan, error) {
	outputReferences := make([]EntityRef, 0, len(outputs))
	for _, output := range outputs {
		outputReferences = append(outputReferences, output.Reference)
	}
	slices.SortFunc(outputReferences, compareEntityRef)
	var authorization *string
	if authorizationDigest != "" {
		value := authorizationDigest
		authorization = &value
	}
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		DecisionID: metadata.DecisionID, OperationID: metadata.OperationID, Operation: operation, Scope: metadata.Scope,
		ActorID: metadata.ActorID, ActorRevision: metadata.ActorRevision, AuthorizationDecisionDigest: authorization,
		ReversesHistoryDigest: metadata.ReversesHistoryDigest, InputEntities: cloneSlice(inputs),
		OutputEntities: outputReferences, Partitions: cloneSlice(partitions),
		SupportingEvidence: cloneSlice(metadata.SupportingEvidence),
		Counterevidence:    cloneSlice(metadata.Counterevidence), Confidence: metadata.Confidence,
		Reason: metadata.Reason, CreatedAt: metadata.CreatedAt}
	decisionCanonical, decisionDigest, err := canonicalValue(decision)
	if err != nil {
		return TransitionPlan{}, err
	}
	parentDigests := cloneSlice(parents)
	slices.Sort(parentDigests)
	if !validDigestSet(parentDigests) {
		return TransitionPlan{}, newError(InvalidInputError, TransitionInvalid, nil)
	}
	history := History{SchemaVersion: HistorySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		HistoryID: metadata.HistoryID, Sequence: metadata.HistorySequence, Scope: metadata.Scope, Operation: operation,
		DecisionDigest: decisionDigest, InputEntities: cloneSlice(inputs), OutputEntities: outputReferences,
		PreviousHistoryDigests: parentDigests, ReversesHistoryDigest: metadata.ReversesHistoryDigest, CreatedAt: metadata.CreatedAt}
	historyCanonical, historyDigest, err := canonicalValue(history)
	if err != nil {
		return TransitionPlan{}, err
	}
	bindDrafts(outputs, decisionDigest, historyDigest)
	bindDrafts(superseded, decisionDigest, historyDigest)
	return TransitionPlan{Operation: operation, Superseded: superseded, Outputs: outputs, Decision: decision,
		DecisionCanonical: decisionCanonical, DecisionDigest: decisionDigest, History: history,
		HistoryCanonical: historyCanonical, HistoryDigest: historyDigest, AuthorizationDecisionDigest: authorizationDigest}, nil
}

func bindDrafts(values []EntityRevisionDraft, decisionDigest, historyDigest string) {
	for index := range values {
		values[index].Entity.CreationDecisionDigest = decisionDigest
		values[index].Entity.HistoryHeadDigest = historyDigest
	}
}

func supersededDraft(ctx context.Context, input Entity, updatedAt string) (EntityRevisionDraft, error) {
	value := input
	value.Revision++
	value.Status = "superseded"
	value.UpdatedAt = updatedAt
	value.CreationDecisionDigest, value.HistoryHeadDigest, value.AuditDigest, value.ProvenanceDigest = "", "", "", ""
	value.PreviousProvenanceDigests = []string{input.ProvenanceDigest}
	_, digest, err := EntityRecordDigest(ctx, value)
	if err != nil {
		return EntityRevisionDraft{}, err
	}
	return EntityRevisionDraft{Entity: value, Reference: EntityRef{EntityID: value.EntityID, Revision: value.Revision, RecordDigest: digest}}, nil
}

func newActiveDraft(ctx context.Context, entityID string, scope Scope, classification string, members []ObservationRef,
	aliases []AliasProof, confidence Confidence, previousProvenanceDigests []string, createdAt string) (EntityRevisionDraft, error) {
	value := Entity{SchemaVersion: EntitySchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		EntityID: entityID, Revision: 1, Scope: scope, Status: "active", Classification: classification,
		MemberObservations: cloneSlice(members), AliasProofs: cloneSlice(aliases),
		Confidence: confidence, PreviousProvenanceDigests: cloneSlice(previousProvenanceDigests),
		CreatedAt: createdAt, UpdatedAt: createdAt}
	_, digest, err := EntityRecordDigest(ctx, value)
	if err != nil {
		return EntityRevisionDraft{}, err
	}
	return EntityRevisionDraft{Entity: value, Reference: EntityRef{EntityID: entityID, Revision: 1, RecordDigest: digest}}, nil
}

func compareEntityRef(left, right EntityRef) int {
	if comparison := compareString(left.EntityID, right.EntityID); comparison != 0 {
		return comparison
	}
	if left.Revision < right.Revision {
		return -1
	}
	if left.Revision > right.Revision {
		return 1
	}
	return compareString(left.RecordDigest, right.RecordDigest)
}

func ensureNewEntityIDs(ctx context.Context, store EntityStore, scope Scope, entityIDs []string) error {
	seen := make(map[string]struct{}, len(entityIDs))
	for _, entityID := range entityIDs {
		if !uuidPattern.MatchString(entityID) {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		if _, duplicate := seen[entityID]; duplicate {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		seen[entityID] = struct{}{}
		_, _, found, err := store.LoadCurrentEntity(ctx, scope, entityID)
		if err = dependencyError(ctx, err); err != nil {
			return err
		}
		if found {
			return newError(ConflictError, RevisionConflict, nil)
		}
	}
	return nil
}

func verifyAliasProofs(ctx context.Context, verifier MatchVerifier, scope Scope, aliases []AliasProof) error {
	if len(aliases) == 0 {
		return nil
	}
	if nilDependency(verifier) {
		return newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	for _, alias := range aliases {
		decision, err := verifier.VerifyAlias(ctx, scope, alias)
		if err = dependencyError(ctx, err); err != nil {
			return err
		}
		if !decision.Verified || decision.KeyRevision != alias.ToKeyRevision || decision.DecisionDigest != alias.VerifierDecisionDigest {
			return newError(DeniedError, IdentifierIncompatible, nil)
		}
	}
	return nil
}
