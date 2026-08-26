package retrievalguard

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type Controller struct {
	authority Authority
	inspector Inspector
	verifier  ArtifactVerifier
	auditor   Auditor
	store     Store
	clock     Clock
}

func New(authority Authority, inspector Inspector, verifier ArtifactVerifier, auditor Auditor, store Store, clock Clock) (*Controller, error) {
	if authority == nil || inspector == nil || verifier == nil || auditor == nil || store == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{authority, inspector, verifier, auditor, store, clock}, nil
}

func (controller *Controller) Inspect(ctx context.Context, request Request) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateRequest(request, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	intent, err := RequestBindingDigest(request)
	if err != nil {
		return Result{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	recovered, found, err := controller.store.Load(opCtx, request.Case, request.TaskID, idempotency)
	if err != nil {
		return Result{}, err
	}
	if found {
		return controller.replay(opCtx, request, intent, recovered, now)
	}
	decision, err := controller.authorize(opCtx, request, intent, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.auditDenial(ctx, request, decision, decision.ReasonCode, now)
	}
	inspection, inspectErr := controller.inspector.Inspect(opCtx, InspectionRequest{Source: request.Source, Profile: cloneProfile(request.Profile), IntentDigest: intent, Deadline: request.Deadline})
	if inspectErr != nil {
		reason := "inspection_unavailable"
		if opCtx.Err() == context.Canceled {
			reason = "inspection_canceled"
		}
		if opCtx.Err() == context.DeadlineExceeded {
			reason = "inspection_timeout"
		}
		if auditErr := controller.appendDenial(ctx, request, decision, reason, now); auditErr != nil {
			return Result{}, auditErr
		}
		return Result{}, mapDependency(opCtx, reason, inspectErr)
	}
	if err = validateInspection(inspection, request); err != nil {
		if auditErr := controller.appendDenial(ctx, request, decision, "inspection_invalid", now); auditErr != nil {
			return Result{}, auditErr
		}
		return Result{}, err
	}
	if err = controller.verifier.VerifyArtifact(opCtx, inspection.Sanitized); err != nil {
		if auditErr := controller.appendDenial(ctx, request, decision, "sanitized_unavailable", now); auditErr != nil {
			return Result{}, auditErr
		}
		return Result{}, mapDependency(opCtx, "sanitized_unavailable", err)
	}
	event, eventDigest, err := allowedEvent(request, intent, decision, inspection, now)
	if err != nil {
		return Result{}, err
	}
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, Request: cloneRequest(request), IntentDigest: intent,
		IdempotencyDigest: idempotency, DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		Inspection: cloneInspection(inspection), AuditEventDigest: eventDigest, PreviousProvenanceDigest: request.Source.ProvenanceDigest, CreatedAt: now, Revision: 1}
	record.ProvenanceDigest, err = provenanceDigest(record)
	if err != nil || validateRecord(record) != nil {
		return Result{}, newError(Internal, "record_build_failed", false, err)
	}
	stored, replayed, err := controller.store.Commit(opCtx, request.IdempotencyKey, record)
	if err != nil {
		return Result{}, err
	}
	if validateRecord(stored) != nil || stored.IntentDigest != intent {
		return Result{}, newError(Denied, "store_result_invalid", false, nil)
	}
	if replayed {
		event, eventDigest, err = allowedEvent(stored.Request, stored.IntentDigest,
			Decision{DecisionDigest: stored.DecisionDigest, RevocationDigest: stored.RevocationDigest}, stored.Inspection, stored.CreatedAt)
		if err != nil || eventDigest != stored.AuditEventDigest {
			return Result{}, newError(Denied, "replayed_audit_invalid", false, nil)
		}
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	if replayed {
		if err = controller.appendAudit(ctx, replayAllowedEvent(request, decision, stored)); err != nil {
			return Result{}, err
		}
	}
	return resultFromRecord(stored, replayed), nil
}

func (controller *Controller) replay(ctx context.Context, request Request, intent string, record Record, now time.Time) (Result, error) {
	if validateRecord(record) != nil || record.IntentDigest != intent {
		if err := controller.appendDenial(ctx, request, Decision{}, "changed_replay", now); err != nil {
			return Result{}, err
		}
		return Result{}, newError(Denied, "changed_replay", false, nil)
	}
	decision, err := controller.authorize(ctx, request, intent, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.auditDenial(ctx, request, decision, decision.ReasonCode, now)
	}
	if err = controller.verifier.VerifyArtifact(ctx, record.Inspection.Sanitized); err != nil {
		if auditErr := controller.appendDenial(ctx, request, decision, "sanitized_unavailable", now); auditErr != nil {
			return Result{}, auditErr
		}
		return Result{}, mapDependency(ctx, "sanitized_unavailable", err)
	}
	event, eventDigest, err := allowedEvent(record.Request, record.IntentDigest,
		Decision{DecisionDigest: record.DecisionDigest, RevocationDigest: record.RevocationDigest}, record.Inspection, record.CreatedAt)
	if err != nil || eventDigest != record.AuditEventDigest {
		if auditErr := controller.appendDenial(ctx, request, decision, "audit_proof_invalid", now); auditErr != nil {
			return Result{}, auditErr
		}
		return Result{}, newError(Denied, "audit_proof_invalid", false, nil)
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	replayEvent := replayAllowedEvent(request, decision, record)
	if err = controller.appendAudit(ctx, replayEvent); err != nil {
		return Result{}, err
	}
	return resultFromRecord(record, true), nil
}

func (controller *Controller) authorize(ctx context.Context, request Request, intent string, now time.Time) (Decision, error) {
	authorization := AuthorizationRequest{RequestDigest: intent, RequestID: request.RequestID, Case: request.Case, TaskID: request.TaskID, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Source: request.Source, Profile: cloneProfile(request.Profile), PolicyDigest: request.PolicyDigest, Deadline: request.Deadline}
	if err := validateAuthorization(authorization); err != nil {
		return Decision{}, err
	}
	decision, err := controller.authority.AuthorizeRetrieval(ctx, authorization)
	if err != nil {
		return Decision{}, mapDependency(ctx, "authority_unavailable", err)
	}
	copyValue := decision
	copyValue.DecisionDigest = ""
	bound, digestErr := DecisionBindingDigest(copyValue)
	if digestErr != nil || decision.DecisionDigest != bound || decision.RequestDigest != intent || decision.Case != request.Case || decision.TaskID != request.TaskID ||
		decision.ActorID != request.ActorID || decision.ActorRevision != request.ActorRevision || decision.PolicyDigest != request.PolicyDigest ||
		decision.IssuedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(request.Deadline) {
		return Decision{}, newError(Denied, "decision_invalid", false, nil)
	}
	return decision, nil
}

func (controller *Controller) auditDenial(ctx context.Context, request Request, decision Decision, reason string, now time.Time) error {
	if err := controller.appendDenial(ctx, request, decision, reason, now); err != nil {
		return err
	}
	return newError(Denied, reason, false, nil)
}

func (controller *Controller) appendDenial(ctx context.Context, request Request, decision Decision, reason string, now time.Time) error {
	evidence := sortedDigests(request.Source.Artifact.Digest, request.Source.ProvenanceDigest, request.Profile.ProfileDigest, request.PolicyDigest, decision.DecisionDigest, decision.RevocationDigest)
	identity := decision.DecisionDigest
	occurredAt := decision.IssuedAt
	if identity == "" || !validTime(occurredAt) {
		intent, _ := RequestBindingDigest(request)
		identity = intent + "\x00" + formatTime(now)
		occurredAt = now
	}
	event := auditEvent(request, "denied", reason, request.Source.Artifact.Digest, evidence, identity, occurredAt)
	return controller.appendAudit(ctx, event)
}

func allowedEvent(request Request, intent string, decision Decision, inspection InspectionResult, now time.Time) (tamperaudit.Event, string, error) {
	evidence := sortedDigests(request.Source.Artifact.Digest, request.Source.ProvenanceDigest, request.Profile.ProfileDigest, request.PolicyDigest,
		decision.DecisionDigest, decision.RevocationDigest, inspection.Sanitized.Digest, inspection.FindingsDigest, inspection.InspectorDigest)
	event := auditEvent(request, "allowed", "content_sanitized", inspection.Sanitized.Digest, evidence, intent, now)
	bound, err := AuditEventBindingDigest(event)
	return event, bound, err
}

func replayAllowedEvent(request Request, decision Decision, record Record) tamperaudit.Event {
	evidence := sortedDigests(request.Source.Artifact.Digest, request.Source.ProvenanceDigest,
		request.Profile.ProfileDigest, request.PolicyDigest, decision.DecisionDigest,
		decision.RevocationDigest, record.Inspection.Sanitized.Digest,
		record.AuditEventDigest, record.ProvenanceDigest)
	return auditEvent(request, "allowed", "replay_authorized", record.Inspection.Sanitized.Digest,
		evidence, decision.DecisionDigest, decision.IssuedAt)
}

func auditEvent(request Request, outcome, reason, subjectDigest string, evidence []string, identity string, now time.Time) tamperaudit.Event {
	return tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-RETRIEVAL-AUDIT-ID-V1\x00", request.RequestID+"\x00"+identity+"\x00"+outcome+"\x00"+reason),
		OrganizationID: request.Case.OrganizationID, TenantID: request.Case.TenantID, CaseID: request.Case.CaseID, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, SourceSchema: RequestSchemaVersion, Operation: "retrieval.inspect", Outcome: outcome, ReasonCode: reason,
		SubjectID: request.RequestID, SubjectRevision: 1, SubjectDigest: subjectDigest, EvidenceDigests: evidence, OccurredAt: formatTime(now)}
}

func (controller *Controller) appendAudit(ctx context.Context, event tamperaudit.Event) error {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := controller.auditor.AppendAuditEvent(auditCtx, event); err != nil {
		return newError(Unavailable, "audit_unavailable", true, nil)
	}
	return nil
}
func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(Internal, "clock_invalid", false, nil)
	}
	return now, nil
}
func resultFromRecord(value Record, replayed bool) Result {
	return Result{Inspection: cloneInspection(value.Inspection), AuditEventDigest: value.AuditEventDigest, ProvenanceDigest: value.ProvenanceDigest, Replayed: replayed}
}
func sortedDigests(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if digestPattern.MatchString(value) && !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
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
