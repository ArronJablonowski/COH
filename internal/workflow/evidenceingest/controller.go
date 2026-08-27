package evidenceingest

import (
	"context"
	"errors"
	"io"
	"math"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const manifestMediaType = "application/vnd.coh.artifact-manifest+json"

type Controller struct {
	authority Authority
	transport TransportVerifier
	cases     CaseStore
	cas       EncryptedCAS
	manifests ManifestStore
	auditor   Auditor
	clock     Clock
}

func New(authority Authority, transport TransportVerifier, cases CaseStore, cas EncryptedCAS,
	manifests ManifestStore, auditor Auditor, clock Clock) (*Controller, error) {
	if authority == nil || transport == nil || cases == nil || cas == nil || manifests == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{authority: authority, transport: transport, cases: cases, cas: cas,
		manifests: manifests, auditor: auditor, clock: clock}, nil
}

func (controller *Controller) Execute(ctx context.Context, command Command, source Source) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateCommand(command, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, command.Deadline, now)
	defer cancel()
	intent, err := CommandBindingDigest(command)
	if err != nil {
		return Result{}, err
	}
	idempotency := IdempotencyBindingDigest(command.IdempotencyKey)
	recovered, found, err := controller.manifests.Recover(opCtx, command.Case, idempotency)
	if err != nil {
		return Result{}, mapDependency(opCtx, "receipt_recovery_unavailable", err)
	}
	if found {
		return controller.replay(opCtx, command, intent, idempotency, recovered, now)
	}
	if source == nil {
		return Result{}, newError(InvalidInput, "source_required", false, nil)
	}
	if err = controller.verifyTransport(opCtx, command.Transport); err != nil {
		return Result{}, err
	}
	current, err := controller.loadCase(opCtx, command.Case)
	if err != nil {
		if CodeOf(err) == NotFound {
			return Result{}, controller.deny(ctx, command, intent, Decision{}, "case_not_found", now)
		}
		return Result{}, err
	}
	decision, err := controller.authorize(opCtx, command, intent, current, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.deny(ctx, command, intent, decision, decision.ReasonCode, now)
	}
	artifact, err := controller.publishArtifact(opCtx, command, source)
	if err != nil {
		return Result{}, err
	}
	event := allowedEvent(command, intent, decision, now)
	auditDigest, err := auditEventBindingDigest(event)
	if err != nil {
		return Result{}, err
	}
	manifest, canonical, manifestRef, err := buildManifest(command, decision, artifact, auditDigest, now)
	if err != nil {
		return Result{}, err
	}
	manifestObject, err := controller.publishManifest(opCtx, command, manifestRef, canonical)
	if err != nil {
		return Result{}, err
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, Case: command.Case, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, IntentDigest: intent, IdempotencyDigest: idempotency,
		AuthorizationDigest: decision.AuthorizationDigest, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, TransportDigest: decision.TransportDigest,
		Artifact: manifest.Artifact, Manifest: manifestRef, EncryptedArtifact: publishedObject(artifact),
		EncryptedManifest: publishedObject(manifestObject), ManifestProvenanceDigest: manifest.ProvenanceDigest,
		AuditEventDigest: auditDigest, CreatedAt: now}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || validateReceipt(receipt) != nil {
		return Result{}, newError(InternalFailure, "receipt_build_failed", false, err)
	}
	stored, replayed, err := controller.manifests.Commit(opCtx, command.IdempotencyKey, intent, receipt)
	if err != nil {
		return Result{}, mapDependency(opCtx, "receipt_commit_unavailable", err)
	}
	if err = validateStoredReceipt(stored, command, intent, idempotency); err != nil {
		return Result{}, err
	}
	if replayed {
		if err = controller.resolveReceipt(opCtx, stored); err != nil {
			return Result{}, err
		}
		event, err = allowedEventFromReceipt(command, stored)
		if err != nil {
			return Result{}, err
		}
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	if replayed {
		if err = controller.appendAudit(ctx, replayEvent(command, decision, stored, now)); err != nil {
			return Result{}, err
		}
	}
	return resultFromReceipt(stored, replayed), nil
}

func (controller *Controller) replay(ctx context.Context, command Command, intent, idempotency string,
	receipt Receipt, now time.Time) (Result, error) {
	if err := validateStoredReceipt(receipt, command, intent, idempotency); err != nil {
		return Result{}, controller.deny(ctx, command, intent, Decision{}, Reason(err), now)
	}
	if err := controller.verifyTransport(ctx, command.Transport); err != nil {
		return Result{}, err
	}
	current, err := controller.loadCase(ctx, command.Case)
	if err != nil {
		return Result{}, err
	}
	decision, err := controller.authorize(ctx, command, intent, current, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != "allow" {
		return Result{}, controller.deny(ctx, command, intent, decision, decision.ReasonCode, now)
	}
	if err = controller.resolveReceipt(ctx, receipt); err != nil {
		return Result{}, err
	}
	event, err := allowedEventFromReceipt(command, receipt)
	if err != nil {
		return Result{}, err
	}
	if err = controller.appendAudit(ctx, event); err != nil {
		return Result{}, err
	}
	if err = controller.appendAudit(ctx, replayEvent(command, decision, receipt, now)); err != nil {
		return Result{}, err
	}
	return resultFromReceipt(receipt, true), nil
}

func (controller *Controller) verifyTransport(ctx context.Context, transport TransportContext) error {
	if err := controller.transport.VerifyTransport(ctx, transport); err != nil {
		return mapDependency(ctx, "transport_verification_unavailable", err)
	}
	return nil
}

func (controller *Controller) loadCase(ctx context.Context, scope domain.CaseRef) (CaseSnapshot, error) {
	value, found, err := controller.cases.LoadCase(ctx, scope)
	if err != nil {
		return CaseSnapshot{}, mapDependency(ctx, "case_load_unavailable", err)
	}
	if !found {
		return CaseSnapshot{}, newError(NotFound, "case_not_found", false, nil)
	}
	if !validCaseSnapshot(value) || value.Case != scope {
		return CaseSnapshot{}, newError(Denied, "case_snapshot_invalid", false, nil)
	}
	return value, nil
}

func (controller *Controller) authorize(ctx context.Context, command Command, intent string,
	current CaseSnapshot, now time.Time) (Decision, error) {
	request := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command), CaseRevision: current.Revision,
		CaseState: current.State, CaseClassification: current.Classification,
		CaseProvenanceDigest: current.ProvenanceDigest}
	request.AuthorizationDigest, _ = AuthorizationBindingDigest(request)
	if err := validateAuthorization(request); err != nil {
		return Decision{}, err
	}
	decision, err := controller.authority.AuthorizeIngestion(ctx, request)
	if err != nil {
		return Decision{}, mapDependency(ctx, "authority_unavailable", err)
	}
	transportDigest, _ := TransportBindingDigest(command.Transport)
	if validateDecision(decision) != nil || decision.AuthorizationDigest != request.AuthorizationDigest ||
		decision.IntentDigest != intent || decision.Case != command.Case || decision.ActorID != command.ActorID ||
		decision.ActorRevision != command.ActorRevision || decision.ArtifactDigest != command.ExpectedDigest ||
		decision.ArtifactLength != command.ExpectedLength || decision.PolicyDigest != command.PolicyDigest ||
		decision.KeyProfileDigest != command.KeyProfileDigest || decision.TransportDigest != transportDigest ||
		decision.IssuedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(command.Deadline) {
		return Decision{}, newError(Denied, "decision_binding_invalid", false, nil)
	}
	return decision, nil
}

func (controller *Controller) publishArtifact(ctx context.Context, command Command,
	source Source) (EncryptedObject, error) {
	request := stageRequest(command.Case, command.ExpectedDigest, command.ExpectedLength, command.MediaType,
		command.Classification, command.KeyProfile, command.KeyProfileDigest, command.Deadline)
	return controller.stageAndPublish(ctx, request, source)
}

func (controller *Controller) publishManifest(ctx context.Context, command Command, reference domain.ArtifactRef,
	canonical []byte) (EncryptedObject, error) {
	request := stageRequest(command.Case, reference.Digest, reference.Length, reference.MediaType,
		reference.Classification, command.KeyProfile, command.KeyProfileDigest, command.Deadline)
	return controller.stageAndPublish(ctx, request, &byteSource{value: canonical})
}

func (controller *Controller) stageAndPublish(ctx context.Context, request StageRequest,
	source Source) (EncryptedObject, error) {
	staged, err := controller.cas.Stage(ctx, request, source)
	if err != nil {
		return EncryptedObject{}, mapDependency(ctx, "cas_stage_unavailable", err)
	}
	if !objectMatchesStage(staged, request) || (staged.Status != Staged && staged.Status != Verified) {
		_ = controller.cas.Abandon(context.WithoutCancel(ctx), staged)
		return EncryptedObject{}, newError(Denied, "cas_stage_invalid", false, nil)
	}
	if err = controller.cas.Verify(ctx, staged); err != nil {
		_ = controller.cas.Abandon(context.WithoutCancel(ctx), staged)
		return EncryptedObject{}, mapDependency(ctx, "cas_verify_unavailable", err)
	}
	published, _, err := controller.cas.Publish(ctx, staged)
	if err != nil {
		return EncryptedObject{}, mapDependency(ctx, "cas_publish_unavailable", err)
	}
	if published.Status != Published || !objectMatchesStage(published, request) {
		return EncryptedObject{}, newError(Denied, "cas_publication_invalid", false, nil)
	}
	resolved, err := controller.cas.Resolve(ctx, publishedObject(published))
	if err != nil {
		return EncryptedObject{}, mapDependency(ctx, "cas_publication_resolution_unavailable", err)
	}
	if resolved != published {
		return EncryptedObject{}, newError(Denied, "cas_publication_resolution_invalid", false, nil)
	}
	return published, nil
}

func objectMatchesStage(value EncryptedObject, request StageRequest) bool {
	if _, err := EncryptedObjectBindingDigest(value); err != nil {
		return false
	}
	return value.Case == request.Case && value.PlaintextDigest == request.ExpectedDigest &&
		value.PlaintextLength == request.ExpectedLength && value.MediaType == request.MediaType &&
		value.Classification == request.Classification &&
		value.EncryptionContextDigest == request.EncryptionContextDigest
}

func stageRequest(scope domain.CaseRef, digestValue string, length int64, mediaType, classification,
	keyProfile, keyProfileDigest string, deadline time.Time) StageRequest {
	value := StageRequest{Case: scope, ExpectedDigest: digestValue, ExpectedLength: length,
		MediaType: mediaType, Classification: classification, KeyProfile: keyProfile,
		KeyProfileDigest: keyProfileDigest, Deadline: deadline}
	value.EncryptionContextDigest, _ = EncryptionContextBindingDigest(value)
	return value
}

func buildManifest(command Command, decision Decision, artifact EncryptedObject, auditDigest string,
	now time.Time) (ArtifactManifest, []byte, domain.ArtifactRef, error) {
	manifest := ArtifactManifest{SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID: deterministicUUID("COH-EVIDENCE-MANIFEST-ID-V1\x00", command.RequestID+"\x00"+decision.DecisionDigest),
		Case:       command.Case, Artifact: domain.ArtifactRef{Digest: artifact.PlaintextDigest,
			MediaType: artifact.MediaType, Classification: artifact.Classification, Length: artifact.PlaintextLength},
		Source: cloneSource(command.Source), ParentArtifacts: append([]domain.ArtifactRef{}, command.ParentArtifacts...),
		ParentManifestDigests: append([]string{}, command.ParentManifestDigests...),
		Components:            append([]ComponentVersion{}, command.Components...), ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, PolicyDigest: command.PolicyDigest,
		AuthorizationDigest: decision.AuthorizationDigest, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, TransportDigest: decision.TransportDigest,
		EncryptionContextDigest: artifact.EncryptionContextDigest, AuditEventDigest: auditDigest,
		CreatedAt: now, Revision: 1}
	manifest.ProvenanceDigest, _ = ManifestProvenanceDigest(manifest)
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return ArtifactManifest{}, nil, domain.ArtifactRef{}, newError(InternalFailure, "manifest_build_failed", false, err)
	}
	reference := domain.ArtifactRef{Digest: contentDigest(canonical), MediaType: manifestMediaType,
		Classification: command.Classification, Length: int64(len(canonical))}
	return manifest, canonical, reference, nil
}

func (controller *Controller) resolveReceipt(ctx context.Context, receipt Receipt) error {
	if _, err := controller.cas.Resolve(ctx, receipt.EncryptedArtifact); err != nil {
		return mapDependency(ctx, "artifact_resolution_unavailable", err)
	}
	if _, err := controller.cas.Resolve(ctx, receipt.EncryptedManifest); err != nil {
		return mapDependency(ctx, "manifest_resolution_unavailable", err)
	}
	return nil
}

func validateStoredReceipt(value Receipt, command Command, intent, idempotency string) error {
	artifact := domain.ArtifactRef{Digest: command.ExpectedDigest, MediaType: command.MediaType,
		Classification: command.Classification, Length: command.ExpectedLength}
	if validateReceipt(value) != nil || value.RequestID != command.RequestID || value.Case != command.Case ||
		value.ActorID != command.ActorID || value.ActorRevision != command.ActorRevision ||
		value.IntentDigest != intent || value.IdempotencyDigest != idempotency || value.Artifact != artifact {
		return newError(Denied, "stored_receipt_invalid", false, nil)
	}
	return nil
}

func resultFromReceipt(value Receipt, replayed bool) Result {
	return Result{Artifact: value.Artifact, Manifest: value.Manifest, Receipt: cloneReceipt(value), Replayed: replayed}
}

func publishedObject(value EncryptedObject) PublishedObject {
	return PublishedObject{Case: value.Case, PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func validCaseSnapshot(value CaseSnapshot) bool {
	return validCase(value.Case) && value.Revision > 0 && value.Revision <= math.MaxInt64 &&
		(value.State == "open" || value.State == "closed") && validClassification(value.Classification) &&
		digestPattern.MatchString(value.ProvenanceDigest)
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	return now, nil
}

func operationContext(ctx context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, deadline.Sub(now))
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	if err == nil {
		return newError(Unavailable, reason, true, nil)
	}
	if CodeOf(err) != Unavailable {
		return err
	}
	if coded, ok := err.(interface{ ErrorCode() string }); ok {
		switch Code(coded.ErrorCode()) {
		case InvalidInput, Denied, NotFound, Conflict, Canceled, Timeout, InternalFailure:
			return newError(Code(coded.ErrorCode()), reason, false, err)
		}
	}
	return newError(Unavailable, reason, true, err)
}

type byteSource struct {
	value  []byte
	offset int
}

func (source *byteSource) ReadContext(ctx context.Context, output []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	if source.offset == len(source.value) {
		return 0, io.EOF
	}
	count := copy(output, source.value[source.offset:])
	source.offset += count
	return count, nil
}
