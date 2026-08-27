package queryevidence

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

type Controller struct {
	ingestor NativeQueryIngestor
	store    EvidenceStore
	auditor  Auditor
	clock    Clock
}

func New(ingestor NativeQueryIngestor, store EvidenceStore, auditor Auditor, clock Clock) (*Controller, error) {
	if ingestor == nil || store == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", nil)
	}
	return &Controller{ingestor: ingestor, store: store, auditor: auditor, clock: clock}, nil
}

func (controller *Controller) Start(ctx context.Context, command StartCommand, source Source) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateStart(command, now); err != nil {
		return Result{}, err
	}
	stream := streamFromSession(command.RuntimeSession)
	opCtx, cancel := operationContext(ctx, command.Deadline, now)
	defer cancel()
	if recovered, found, recoverErr := controller.store.Recover(opCtx, stream, command.IdempotencyKey); recoverErr != nil {
		return Result{}, dependencyError(opCtx, "record_recovery_unavailable", recoverErr)
	} else if found {
		if err = validateRecoveredStart(recovered, command); err != nil {
			return Result{}, err
		}
		return controller.finish(ctx, recovered, true)
	}
	if source == nil {
		return Result{}, newError(InvalidInput, "native_query_source_required", nil)
	}
	binding, err := controller.ingestor.IngestNativeQuery(opCtx, artifactRequest(command, now), source)
	if err != nil {
		return Result{}, ingestError(opCtx, err)
	}
	if !validArtifact(binding) || binding.Artifact.Digest != command.NativeQueryDigest ||
		binding.Artifact.Length != command.NativeQueryLength || binding.Artifact.MediaType != command.NativeQueryMediaType ||
		binding.Artifact.Classification != command.Classification {
		return Result{}, newError(Conflict, "native_query_binding_invalid", nil)
	}
	record, err := buildStart(command, binding, now)
	if err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.store.Append(opCtx, ExpectedHead{}, command.IdempotencyKey, record.TransitionID, record)
	if err != nil {
		return Result{}, dependencyError(opCtx, "record_append_unavailable", err)
	}
	if err = validateStored(stored, record); err != nil {
		return Result{}, err
	}
	return controller.finish(ctx, stored, replayed)
}

func (controller *Controller) Transition(ctx context.Context, command TransitionCommand) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateTransition(command, now); err != nil {
		return Result{}, err
	}
	stream := streamFromSession(command.RuntimeSession)
	opCtx, cancel := operationContext(ctx, command.Deadline, now)
	defer cancel()
	if recovered, found, recoverErr := controller.store.Recover(opCtx, stream, command.IdempotencyKey); recoverErr != nil {
		return Result{}, dependencyError(opCtx, "record_recovery_unavailable", recoverErr)
	} else if found {
		if err = validateRecoveredTransition(recovered, command); err != nil {
			return Result{}, err
		}
		return controller.finish(ctx, recovered, true)
	}
	head, found, err := controller.store.LoadHead(opCtx, stream)
	if err != nil {
		return Result{}, dependencyError(opCtx, "record_head_unavailable", err)
	}
	if !found {
		return Result{}, newError(Conflict, "query_evidence_start_missing", nil)
	}
	if err = VerifyRecord(head); err != nil {
		return Result{}, err
	}
	record, err := buildTransition(head, command, now)
	if err != nil {
		return Result{}, err
	}
	expected := ExpectedHead{Revision: head.Revision, ProvenanceDigest: head.ProvenanceDigest}
	stored, replayed, err := controller.store.Append(opCtx, expected, command.IdempotencyKey, record.TransitionID, record)
	if err != nil {
		return Result{}, dependencyError(opCtx, "record_append_unavailable", err)
	}
	if err = validateStored(stored, record); err != nil {
		return Result{}, err
	}
	return controller.finish(ctx, stored, replayed)
}

// RecordQuerySession satisfies queryruntime.Recorder. Page content remains on
// its encrypted evidence path; this method records the exact runtime/result
// digest before the broker releases a page or terminal outcome.
func (controller *Controller) RecordQuerySession(ctx context.Context, session queryruntime.Session) error {
	deadline, err := time.Parse(timestampLayout, session.Deadline)
	if err != nil {
		return newError(InvalidInput, "runtime_session_invalid", err)
	}
	_, err = controller.Transition(ctx, TransitionCommand{
		IdempotencyKey:            session.SessionDigest,
		Event:                     eventFromSession(session),
		RuntimeSession:            session,
		ResultDigest:              session.LastPageDigest,
		Completeness:              session.Status,
		ReasonCode:                session.ReasonCode,
		CancellationIntentDigest:  session.CancellationIntentDigest,
		CancellationOutcomeDigest: cancellationOutcomeFromSession(session),
		Deadline:                  deadline,
	})
	return err
}

func (controller *Controller) finish(ctx context.Context, record Record, replayed bool) (Result, error) {
	outcome := "committed"
	if replayed {
		outcome = "replayed"
	}
	event, err := finalizeAudit(AuditEvent{SchemaVersion: AuditSchemaVersion, ContractVersion: ContractVersion,
		TransitionID: record.TransitionID, RecordDigest: record.RecordDigest, ProvenanceDigest: record.ProvenanceDigest,
		Stream: record.Stream, Revision: record.Revision, Event: record.Event, Outcome: outcome, OccurredAt: record.OccurredAt})
	if err != nil {
		return Result{}, err
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), MaximumAuditWait)
	defer cancel()
	if err = controller.auditor.AppendQueryEvidence(auditCtx, event); err != nil {
		return Result{}, dependencyError(auditCtx, "audit_append_unavailable", err)
	}
	return Result{Record: record, Replayed: replayed}, nil
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, newError(Internal, "clock_invalid", nil)
	}
	return now, nil
}

func operationContext(ctx context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	limit := now.Add(MaximumAppendWait)
	if deadline.Before(limit) {
		limit = deadline
	}
	return context.WithTimeout(ctx, limit.Sub(now))
}

func streamFromSession(value queryruntime.Session) StreamRef {
	return StreamRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID, QueryID: value.QueryID, AttemptID: value.AttemptID}
}

func artifactRequest(command StartCommand, now time.Time) ArtifactRequest {
	return ArtifactRequest{RequestID: command.RequestID, IdempotencyKey: command.IdempotencyKey + ".native-query", Case: command.Case,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, SourceID: command.SourceID, QueryDigest: command.QueryDigest,
		ExpectedDigest: command.NativeQueryDigest, ExpectedLength: command.NativeQueryLength,
		MediaType: command.NativeQueryMediaType, Classification: command.Classification, PolicyDigest: command.PolicyDigest,
		CollectedAt: now, Deadline: command.Deadline}
}

func buildStart(command StartCommand, binding ArtifactBinding, now time.Time) (Record, error) {
	session := command.RuntimeSession
	return FinalizeRecord(Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, Revision: 1,
		Stream: streamFromSession(session), Case: caseBinding(command.Case), ActorID: command.ActorID, SourceID: command.SourceID,
		QueryDigest: command.QueryDigest, BoundsDecisionDigest: command.BoundsDecisionDigest, ExecutionDigest: command.ExecutionDigest,
		ValidatorVersion: command.ValidatorVersion, ValidatorProvenanceDigest: command.ValidatorProvenanceDigest,
		IntervalStart: command.IntervalStart, IntervalEnd: command.IntervalEnd, ResourceScopeDigest: command.ResourceScopeDigest,
		NativeQuery: binding, Event: "started", RuntimeSessionRevision: session.Revision, RuntimeSessionDigest: session.SessionDigest,
		Completeness: "running", ReasonCode: "query_started", Statistics: statisticsFromSession(session), OccurredAt: now.Format(timestampLayout)})
}

func buildTransition(head Record, command TransitionCommand, now time.Time) (Record, error) {
	session := command.RuntimeSession
	if head.Stream != streamFromSession(session) || head.QueryDigest != session.QueryDigest || head.ExecutionDigest != session.ExecutionDigest ||
		head.BoundsDecisionDigest != session.BoundsDecisionDigest || session.Revision != head.RuntimeSessionRevision+1 ||
		session.PreviousSessionDigest != head.RuntimeSessionDigest || !monotonic(head.Statistics, statisticsFromSession(session)) || terminal(head.Completeness) {
		return Record{}, newError(Conflict, "transition_lineage_invalid", nil)
	}
	next := head
	next.RecordDigest, next.ProvenanceDigest, next.TransitionID = "", "", ""
	next.PreviousProvenanceDigest = head.ProvenanceDigest
	next.Revision++
	next.Event = command.Event
	next.RuntimeSessionRevision = session.Revision
	next.RuntimeSessionDigest = session.SessionDigest
	next.Result = cloneArtifact(command.Result)
	next.ResultDigest = command.ResultDigest
	next.Completeness = command.Completeness
	next.ReasonCode = command.ReasonCode
	next.Statistics = statisticsFromSession(session)
	next.CancellationIntentDigest = command.CancellationIntentDigest
	next.CancellationOutcomeDigest = command.CancellationOutcomeDigest
	next.OccurredAt = now.Format(timestampLayout)
	return FinalizeRecord(next)
}

func validateStored(stored, expected Record) error {
	if err := VerifyRecord(stored); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(stored.RecordDigest), []byte(expected.RecordDigest)) != 1 ||
		subtle.ConstantTimeCompare([]byte(stored.TransitionID), []byte(expected.TransitionID)) != 1 {
		return newError(Conflict, "stored_record_substituted", nil)
	}
	return nil
}

func validateRecoveredStart(record Record, command StartCommand) error {
	if err := VerifyRecord(record); err != nil {
		return err
	}
	if record.Revision != 1 || record.Stream != streamFromSession(command.RuntimeSession) || record.Case != caseBinding(command.Case) ||
		record.ActorID != command.ActorID || record.SourceID != command.SourceID || record.QueryDigest != command.QueryDigest ||
		record.BoundsDecisionDigest != command.BoundsDecisionDigest || record.ExecutionDigest != command.ExecutionDigest ||
		record.ValidatorVersion != command.ValidatorVersion || record.ValidatorProvenanceDigest != command.ValidatorProvenanceDigest ||
		record.IntervalStart != command.IntervalStart || record.IntervalEnd != command.IntervalEnd ||
		record.ResourceScopeDigest != command.ResourceScopeDigest || record.NativeQuery.Artifact.Digest != command.NativeQueryDigest ||
		record.NativeQuery.Artifact.Length != command.NativeQueryLength || record.NativeQuery.Artifact.MediaType != command.NativeQueryMediaType ||
		record.NativeQuery.Artifact.Classification != command.Classification {
		return newError(Conflict, "idempotency_conflict", nil)
	}
	return nil
}

func validateRecoveredTransition(record Record, command TransitionCommand) error {
	if err := VerifyRecord(record); err != nil {
		return err
	}
	if record.Stream != streamFromSession(command.RuntimeSession) || record.RuntimeSessionDigest != command.RuntimeSession.SessionDigest ||
		record.Event != command.Event || record.ResultDigest != command.ResultDigest || record.Completeness != command.Completeness ||
		record.ReasonCode != command.ReasonCode || record.CancellationIntentDigest != command.CancellationIntentDigest ||
		record.CancellationOutcomeDigest != command.CancellationOutcomeDigest || !sameArtifact(record.Result, command.Result) {
		return newError(Conflict, "idempotency_conflict", nil)
	}
	return nil
}

func statisticsFromSession(value queryruntime.Session) Statistics {
	return Statistics{RowsScanned: value.Usage.RowsScanned, RowsReturned: value.Usage.RowsReturned,
		BytesReturned: value.Usage.BytesReturned, DurationMillis: value.Usage.DurationMillis,
		PagesReturned: value.Usage.PagesReturned, SlicesCompleted: value.Usage.SlicesCompleted, CostMillionths: value.Usage.CostMillionths}
}

func monotonic(previous, next Statistics) bool {
	return next.RowsScanned >= previous.RowsScanned && next.RowsReturned >= previous.RowsReturned &&
		next.BytesReturned >= previous.BytesReturned && next.DurationMillis >= previous.DurationMillis &&
		next.PagesReturned >= previous.PagesReturned && next.SlicesCompleted >= previous.SlicesCompleted &&
		next.CostMillionths >= previous.CostMillionths
}

func terminal(value string) bool { return value != "running" }

func eventFromSession(value queryruntime.Session) string {
	switch value.Status {
	case "complete":
		return "result"
	case "partial":
		return "partial"
	case "truncated":
		return "truncated"
	case "canceled":
		return "canceled"
	case "uncertain":
		return "uncertain"
	case "failed":
		return "failed"
	default:
		if value.LastPageDigest != "" {
			return "page"
		}
		return "validated"
	}
}

func cancellationOutcomeFromSession(value queryruntime.Session) string {
	if value.Status == "canceled" {
		return value.VendorProvenanceDigest
	}
	return ""
}

func cloneArtifact(value *ArtifactBinding) *ArtifactBinding {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func sameArtifact(first, second *ArtifactBinding) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func caseBinding(value domain.CaseRef) CaseBinding {
	return CaseBinding{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func validateStart(command StartCommand, now time.Time) error {
	if !uuidPattern.MatchString(command.RequestID) || command.IdempotencyKey == "" || len(command.IdempotencyKey) > 256 || !validCase(command.Case) ||
		!uuidPattern.MatchString(command.ActorID) || command.ActorRevision == 0 || !tokenPattern.MatchString(command.SourceID) || !validDigest(command.QueryDigest) ||
		!validDigest(command.BoundsDecisionDigest) || !validDigest(command.ExecutionDigest) || !versionPattern.MatchString(command.ValidatorVersion) ||
		!validDigest(command.ValidatorProvenanceDigest) || !validTimestamp(command.IntervalStart) || !validTimestamp(command.IntervalEnd) ||
		!validDigest(command.ResourceScopeDigest) || !validDigest(command.NativeQueryDigest) || command.NativeQueryLength <= 0 ||
		command.NativeQueryLength > 1<<20 || command.NativeQueryMediaType == "" || len(command.NativeQueryMediaType) > 255 ||
		!tokenPattern.MatchString(command.Classification) || !validDigest(command.PolicyDigest) || !command.Deadline.After(now) || queryruntime.VerifySession(command.RuntimeSession) != nil {
		return newError(InvalidInput, "start_command_invalid", nil)
	}
	session := command.RuntimeSession
	if session.Revision != 1 || session.QueryDigest != command.QueryDigest || session.BoundsDecisionDigest != command.BoundsDecisionDigest ||
		session.ExecutionDigest != command.ExecutionDigest || session.OrganizationID != command.Case.OrganizationID ||
		session.TenantID != command.Case.TenantID || session.CaseID != command.Case.CaseID || session.ActorID != command.ActorID || session.SourceID != command.SourceID ||
		session.Status != "running" {
		return newError(Conflict, "start_lineage_invalid", nil)
	}
	return nil
}

func validateTransition(command TransitionCommand, now time.Time) error {
	if command.IdempotencyKey == "" || len(command.IdempotencyKey) > 256 ||
		!oneOf(command.Event, "validated", "page", "result", "truncated", "partial", "cancellation_requested", "canceled", "uncertain", "failed") ||
		!oneOf(command.Completeness, "running", "complete", "partial", "truncated", "canceled", "uncertain", "failed") ||
		!tokenPattern.MatchString(command.ReasonCode) || !validOptionalDigest(command.ResultDigest) ||
		!validOptionalDigest(command.CancellationIntentDigest) || !validOptionalDigest(command.CancellationOutcomeDigest) ||
		(command.Result != nil && (!validArtifact(*command.Result) || command.Result.Artifact.Digest != command.ResultDigest)) ||
		!command.Deadline.After(now) || queryruntime.VerifySession(command.RuntimeSession) != nil {
		return newError(InvalidInput, "transition_command_invalid", nil)
	}
	if command.RuntimeSession.Status != command.Completeness || command.RuntimeSession.ReasonCode != command.ReasonCode ||
		(command.ResultDigest != "" && command.RuntimeSession.LastPageDigest != command.ResultDigest) ||
		command.RuntimeSession.CancellationIntentDigest != command.CancellationIntentDigest || !validEventOutcome(command.Event, command.Completeness) ||
		(command.Event == "canceled" && (command.Completeness != "canceled" || command.CancellationIntentDigest == "" || command.CancellationOutcomeDigest == "")) ||
		(command.Event == "cancellation_requested" && command.CancellationIntentDigest == "") {
		return newError(Conflict, "transition_outcome_invalid", nil)
	}
	return nil
}

func validEventOutcome(event, completeness string) bool {
	switch event {
	case "validated", "page", "cancellation_requested":
		return completeness == "running"
	case "result":
		return completeness == "complete"
	case "partial", "truncated", "canceled", "uncertain", "failed":
		return event == completeness
	default:
		return false
	}
}

var _ queryruntime.Recorder = (*Controller)(nil)
