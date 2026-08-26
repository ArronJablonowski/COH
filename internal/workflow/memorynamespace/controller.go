package memorynamespace

import (
	"context"
	"errors"
	"time"
)

type Controller struct {
	session, caseMemory, analyst, organization Store
	authority                                  Authority
	reviewAuthority                            ReviewAuthority
	clock                                      Clock
}

func New(session, caseMemory, analyst, organization Store, authority Authority,
	reviewAuthority ReviewAuthority, clock Clock) (*Controller, error) {
	if session == nil || caseMemory == nil || analyst == nil || organization == nil ||
		authority == nil || reviewAuthority == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	if session.Namespace() != SessionMemory || caseMemory.Namespace() != CaseMemory ||
		analyst.Namespace() != AnalystPreferenceMemory || organization.Namespace() != ReviewedOrganizationMemory {
		return nil, newError(Denied, "store_namespace_binding_invalid", false, nil)
	}
	return &Controller{session: session, caseMemory: caseMemory, analyst: analyst,
		organization: organization, authority: authority, reviewAuthority: reviewAuthority, clock: clock}, nil
}

func (controller *Controller) Put(ctx context.Context, request PutRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err := validatePut(request, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	intent, err := intentDigest(request)
	if err != nil {
		return Result{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	store := controller.store(request.Namespace)
	if recovered, found, recoverErr := store.Recover(opCtx, request.Scope, request.Key, idempotency); recoverErr != nil {
		return Result{}, recoverErr
	} else if found {
		if validateRecord(recovered) != nil || recovered.IntentDigest != intent {
			return Result{}, newError(Denied, "changed_replay", false, nil)
		}
		valueDigest, digestErr := memoryValueDigest(artifactToWire(recovered.Value), recovered.ValueType)
		if digestErr != nil {
			return Result{}, digestErr
		}
		if _, _, authErr := controller.authorize(opCtx, request, recovered.Retention, valueDigest, now); authErr != nil {
			return Result{}, authErr
		}
		return Result{Record: cloneRecord(recovered), Replayed: true}, nil
	}
	prior, found, err := store.Load(opCtx, request.Scope, request.Key)
	if err != nil {
		return Result{}, err
	}
	if found && validateRecord(prior) != nil {
		return Result{}, newError(Denied, "stored_record_invalid", false, nil)
	}
	if (!found && request.ExpectedRevision != 0) || (found && prior.Revision != request.ExpectedRevision) {
		return Result{}, newError(Conflict, "stale_revision", false, nil)
	}
	valueDigest, err := memoryValueDigest(artifactToWire(request.Value), request.ValueType)
	if err != nil {
		return Result{}, err
	}
	access, review, err := controller.authorize(opCtx, request, request.Retention, valueDigest, now)
	if err != nil {
		return Result{}, err
	}
	createdAt, previous := now, ""
	if found {
		createdAt, previous = prior.CreatedAt, prior.ProvenanceDigest
	}
	record := Record{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		Namespace: request.Namespace, Scope: request.Scope, Key: request.Key, Value: request.Value,
		ValueType: request.ValueType, Retention: request.Retention, Review: request.Review,
		WriterActorID: request.ActorID, PolicyDigest: request.PolicyDigest, IntentDigest: intent,
		IdempotencyDigest: idempotency, AccessDecisionDigest: access.DecisionDigest,
		PreviousProvenanceDigest: previous, CreatedAt: createdAt, UpdatedAt: now,
		Revision: request.ExpectedRevision + 1}
	if request.Namespace == ReviewedOrganizationMemory {
		record.ReviewDecisionDigest = review.DecisionDigest
	}
	record.ProvenanceDigest, err = provenanceDigest(record)
	if err != nil || validateRecord(record) != nil {
		return Result{}, newError(Internal, "record_build_failed", false, err)
	}
	stored, replayed, err := store.Commit(opCtx, request.IdempotencyKey, intent, request.ExpectedRevision, record)
	if err != nil {
		return Result{}, err
	}
	if validateRecord(stored) != nil || stored.IntentDigest != intent || stored.ProvenanceDigest != record.ProvenanceDigest {
		return Result{}, newError(Denied, "store_result_invalid", false, nil)
	}
	return Result{Record: cloneRecord(stored), Replayed: replayed}, nil
}

func (controller *Controller) Get(ctx context.Context, request GetRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err := validateGet(request, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	record, found, err := controller.store(request.Namespace).Load(opCtx, request.Scope, request.Key)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{}, newError(NotFound, "memory_not_found", false, nil)
	}
	if validateRecord(record) != nil || record.Namespace != request.Namespace || record.Scope != request.Scope || record.Key != request.Key {
		return Result{}, newError(Denied, "stored_record_invalid", false, nil)
	}
	if !record.Retention.ExpiresAt.After(now) {
		return Result{}, newError(Denied, "memory_expired", false, nil)
	}
	if record.Namespace == ReviewedOrganizationMemory && !record.Review.ValidUntil.After(now) {
		return Result{}, newError(Denied, "review_expired", false, nil)
	}
	valueDigest, err := memoryValueDigest(artifactToWire(record.Value), record.ValueType)
	if err != nil {
		return Result{}, err
	}
	accessRequest, err := makeAccessRequest(request.RequestID, request.ActorID, Read, request.Namespace,
		request.Scope, request.Key, valueDigest, record.Retention, request.PolicyDigest, request.Deadline)
	if err != nil {
		return Result{}, err
	}
	if _, err = controller.access(opCtx, accessRequest, now); err != nil {
		return Result{}, err
	}
	if record.Namespace == ReviewedOrganizationMemory {
		reviewRequest := ReviewRequest{SchemaVersion: ReviewSchemaVersion, ContractVersion: ContractVersion,
			RequestID: request.RequestID, ActorID: request.ActorID,
			WriterActorID: record.WriterActorID, Operation: Read, Scope: request.Scope, Key: request.Key,
			ValueDigest: valueDigest, Review: record.Review, PolicyDigest: request.PolicyDigest,
			Deadline: request.Deadline}
		if _, err = controller.review(opCtx, reviewRequest, now); err != nil {
			return Result{}, err
		}
	}
	return Result{Record: cloneRecord(record)}, nil
}

func (controller *Controller) authorize(ctx context.Context, request PutRequest, retention RetentionPolicy,
	valueDigest string, now time.Time) (Decision, ReviewDecision, error) {
	accessRequest, err := makeAccessRequest(request.RequestID, request.ActorID, Write, request.Namespace,
		request.Scope, request.Key, valueDigest, retention, request.PolicyDigest, request.Deadline)
	if err != nil {
		return Decision{}, ReviewDecision{}, err
	}
	access, err := controller.access(ctx, accessRequest, now)
	if err != nil {
		return Decision{}, ReviewDecision{}, err
	}
	if request.Namespace != ReviewedOrganizationMemory {
		return access, ReviewDecision{}, nil
	}
	reviewRequest := ReviewRequest{SchemaVersion: ReviewSchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, ActorID: request.ActorID,
		WriterActorID: request.ActorID, Operation: Write, Scope: request.Scope, Key: request.Key,
		ValueDigest: valueDigest, Review: request.Review, PolicyDigest: request.PolicyDigest,
		Deadline: request.Deadline}
	review, err := controller.review(ctx, reviewRequest, now)
	return access, review, err
}

func (controller *Controller) access(ctx context.Context, request AccessRequest, now time.Time) (Decision, error) {
	want, err := AccessDigest(request)
	if err != nil {
		return Decision{}, err
	}
	decision, err := controller.authority.AuthorizeMemory(ctx, request)
	if err != nil {
		return Decision{}, mapDependency(ctx, "access_authority_unavailable", err)
	}
	copyValue := decision
	copyValue.DecisionDigest = ""
	bound, digestErr := DecisionBindingDigest(copyValue)
	if digestErr != nil || decision.AccessRequestDigest != want || decision.DecisionDigest != bound ||
		decision.DecidedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(request.Deadline) {
		return Decision{}, newError(Denied, "access_decision_invalid", false, nil)
	}
	if !decision.Allowed {
		return Decision{}, newError(Denied, decision.ReasonCode, false, nil)
	}
	return decision, nil
}

func (controller *Controller) review(ctx context.Context, request ReviewRequest, now time.Time) (ReviewDecision, error) {
	want, err := ReviewDigest(request)
	if err != nil {
		return ReviewDecision{}, err
	}
	decision, err := controller.reviewAuthority.AuthorizeReview(ctx, request)
	if err != nil {
		return ReviewDecision{}, mapDependency(ctx, "review_authority_unavailable", err)
	}
	copyValue := decision
	copyValue.DecisionDigest = ""
	bound, digestErr := ReviewDecisionBindingDigest(copyValue)
	if digestErr != nil || decision.ReviewRequestDigest != want || decision.DecisionDigest != bound ||
		decision.DecidedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(request.Deadline) ||
		decision.ExpiresAt.After(request.Review.ValidUntil) {
		return ReviewDecision{}, newError(Denied, "review_decision_invalid", false, nil)
	}
	if !decision.Allowed {
		return ReviewDecision{}, newError(Denied, decision.ReasonCode, false, nil)
	}
	return decision, nil
}

func makeAccessRequest(requestID, actorID string, operation Operation, namespace Namespace, scope Scope,
	key, valueDigest string, retention RetentionPolicy, policyDigest string, deadline time.Time) (AccessRequest, error) {
	retentionBound, err := retentionDigest(retention)
	if err != nil {
		return AccessRequest{}, err
	}
	return AccessRequest{SchemaVersion: AccessSchemaVersion, ContractVersion: ContractVersion,
		RequestID: requestID, ActorID: actorID, Operation: operation, Namespace: namespace,
		Scope: scope, Key: key, ValueDigest: valueDigest, RetentionDigest: retentionBound,
		PolicyDigest: policyDigest, Deadline: deadline}, nil
}

func (controller *Controller) store(namespace Namespace) Store {
	switch namespace {
	case SessionMemory:
		return controller.session
	case CaseMemory:
		return controller.caseMemory
	case AnalystPreferenceMemory:
		return controller.analyst
	default:
		return controller.organization
	}
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(Internal, "clock_invalid", false, nil)
	}
	return now, nil
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	if CodeOf(err) != Unavailable {
		return err
	}
	return newError(Unavailable, reason, true, nil)
}

func cloneRecord(value Record) Record { return value }
