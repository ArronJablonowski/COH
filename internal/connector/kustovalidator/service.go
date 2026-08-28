package kustovalidator

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const auditCommitTimeout = 5 * time.Second

type Service struct {
	helper     Helper
	admission  AdmissionControl
	trust      HelperTrust
	revocation RevocationControl
	audit      AuditCommitter
	replay     ReplayStore
	clock      Clock
}

func NewService(helper Helper, admission AdmissionControl, trust HelperTrust, revocation RevocationControl,
	audit AuditCommitter, replay ReplayStore, clock Clock) (*Service, error) {
	if helper == nil || admission == nil || trust == nil || revocation == nil || audit == nil || replay == nil || clock == nil {
		return nil, queryconnector.NewError(queryconnector.InvalidInput, "kusto_dependencies_required", nil)
	}
	return &Service{helper: helper, admission: admission, trust: trust, revocation: revocation,
		audit: audit, replay: replay, clock: clock}, nil
}

func (service *Service) Validate(ctx context.Context, input ValidateRequest) (ValidationAdmission, error) {
	if service == nil || service.helper == nil || service.clock == nil {
		return ValidationAdmission{}, unavailable("kusto_validator_unavailable", nil)
	}
	if err := contextFailure(ctx); err != nil {
		return ValidationAdmission{}, err
	}
	now := service.clock.Now().UTC()
	request, commonQueryDigest, err := projectHelperRequest(ctx, input, now)
	if err != nil {
		return ValidationAdmission{}, err
	}
	attestationDigest := HelperAttestationDigest(input.Helper)
	check := admissionCheck("pre_helper", input, request, "", attestationDigest, now)
	if err := service.verifyCurrent(ctx, input, check); err != nil {
		return ValidationAdmission{}, err
	}

	record, replayed, err := service.replay.BeginKustoValidation(ctx, input.IdempotencyKey, request.RequestDigest)
	if err != nil {
		if errors.Is(err, ErrChangedReplay) {
			return ValidationAdmission{}, queryconnector.NewError(queryconnector.Conflict, "changed_replay", err)
		}
		return ValidationAdmission{}, unavailable("replay_unavailable", err)
	}
	if replayed {
		if err := validateRetained(record, request.RequestDigest, commonQueryDigest); err != nil {
			return ValidationAdmission{}, err
		}
		check.Phase = "replay"
		check.HelperResponseDigest = record.Admission.Decision.ResponseDigest
		if err := service.verifyCurrent(ctx, input, check); err != nil {
			return ValidationAdmission{}, err
		}
		admission := cloneAdmission(record.Admission)
		admission.Replayed = true
		return admission, nil
	}
	completed := false
	defer func() {
		if !completed {
			service.replay.AbandonKustoValidation(context.WithoutCancel(ctx), input.IdempotencyKey, request.RequestDigest)
		}
	}()

	response, helperErr := service.helper.Validate(ctx, request)
	if helperErr != nil {
		if err := contextFailure(ctx); err != nil {
			return ValidationAdmission{}, err
		}
		return ValidationAdmission{}, unavailable("helper_unavailable", helperErr)
	}
	if err := ValidateHelperExchange(request, response); err != nil {
		return ValidationAdmission{}, unavailable("helper_response_invalid", err)
	}
	check = admissionCheck("post_helper", input, request, response.ResponseDigest, attestationDigest, service.clock.Now().UTC())
	if err := service.verifyCurrent(ctx, input, check); err != nil {
		return ValidationAdmission{}, err
	}
	decision := buildDecision(input, request, response, attestationDigest, check.EvaluatedAt)
	auditRequest := buildAudit(input, decision, response)
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditCommitTimeout)
	proof, err := service.audit.CommitKustoValidation(auditCtx, auditRequest)
	cancel()
	if err != nil || validateCommittedAudit(auditRequest, proof) != nil {
		return ValidationAdmission{}, unavailable("audit_unavailable", err)
	}
	if response.Outcome != "accepted" {
		return ValidationAdmission{}, queryconnector.NewError(queryconnector.Denied, response.ReasonCodes[0], nil)
	}
	result := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: input.Query.QueryID, Outcome: "accepted",
		ReasonCodes: []string{}, ValidatorVersion: ValidatorVersion,
		CanonicalQueryDigest: commonQueryDigest,
		ProvenanceDigest:     validationProvenance(request, response, attestationDigest)}
	value := ValidationAdmission{Validation: result, CanonicalKQL: response.CanonicalKQL,
		CanonicalKQLDigest: response.CanonicalKQLDigest, OutputColumns: slices.Clone(response.OutputColumns),
		Decision: decision, Audit: proof}
	if err := service.replay.CompleteKustoValidation(ctx, input.IdempotencyKey,
		ReplayRecord{RequestDigest: request.RequestDigest, Admission: cloneAdmission(value)}); err != nil {
		return ValidationAdmission{}, unavailable("replay_commit_unavailable", err)
	}
	completed = true
	return cloneAdmission(value), nil
}

func (service *Service) verifyCurrent(ctx context.Context, input ValidateRequest, check AdmissionCheck) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	if err := validateAttestation(input.Helper); err != nil {
		return queryconnector.NewError(queryconnector.Denied, "helper_attestation_invalid", err)
	}
	validUntil, _ := parseTimestamp(input.Helper.ValidUntil)
	observedAt, _ := parseTimestamp(input.Helper.ObservedAt)
	capabilityUntil, capabilityOK := parseBoundaryTimestamp(input.Capability.ValidUntil)
	deadline, deadlineOK := parseBoundaryTimestamp(input.Query.Deadline)
	if observedAt.After(check.EvaluatedAt) || !validUntil.After(check.EvaluatedAt) || !capabilityOK ||
		!capabilityUntil.After(check.EvaluatedAt) || !deadlineOK || !deadline.After(check.EvaluatedAt) ||
		!schemaFresh(input.Schema, check.EvaluatedAt) {
		return queryconnector.NewError(queryconnector.Denied, "admission_state_stale", nil)
	}
	if err := service.trust.VerifyKustoHelper(ctx, input.Helper); err != nil {
		return queryconnector.NewError(queryconnector.Denied, "helper_signature_or_qualification_denied", err)
	}
	if err := service.admission.CheckKustoValidation(ctx, check); err != nil {
		return queryconnector.NewError(queryconnector.Denied, "authority_denied", err)
	}
	revocation := RevocationCheck{Phase: check.Phase, QueryID: input.Query.QueryID, ActorID: input.Query.Authority.ActorID,
		RequestDigest: check.HelperRequestDigest, ResponseDigest: check.HelperResponseDigest,
		HelperAttestationDigest: check.HelperAttestationDigest, PolicyDecisionDigest: input.Query.Authority.PolicyDecisionDigest,
		AuditReservationDigest: input.Query.Authority.AuditReservationDigest}
	if err := service.revocation.CheckKustoRevocation(ctx, revocation); err != nil {
		return queryconnector.NewError(queryconnector.Denied, "revoked", err)
	}
	return contextFailure(ctx)
}

func unavailable(reason string, err error) error {
	return queryconnector.NewError(queryconnector.Unavailable, reason, err)
}

func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return queryconnector.NewError(queryconnector.InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
		return queryconnector.NewError(queryconnector.Timeout, "validation_timeout", err)
	}
	if err := ctx.Err(); err != nil {
		return queryconnector.NewError(queryconnector.Canceled, "validation_canceled", err)
	}
	return nil
}

func validateRetained(record ReplayRecord, digest, commonQueryDigest string) error {
	value := record.Admission
	if record.RequestDigest != digest || value.CanonicalKQL == "" || value.Validation.Outcome != "accepted" ||
		value.Validation.CanonicalQueryDigest != commonQueryDigest ||
		value.CanonicalKQLDigest != CanonicalKQLDigest(value.CanonicalKQL) ||
		validateOutputColumns(value.OutputColumns) != nil || validateAudit(value.Audit) != nil ||
		value.Audit.AuditRecordDigest == "" || validateDecision(value.Decision) != nil ||
		value.Decision.Outcome != "accepted" || value.Decision.RequestDigest != digest ||
		value.Validation.QueryID != value.Decision.QueryID || value.Audit.QueryID != value.Decision.QueryID ||
		value.Audit.ActorID != value.Decision.ActorID || value.Audit.ScopeDigest != value.Decision.ScopeDigest ||
		value.Audit.RequestDigest != value.Decision.RequestDigest || value.Audit.ResponseDigest != value.Decision.ResponseDigest ||
		value.Audit.RegistryDigest != value.Decision.RegistryDigest ||
		value.Audit.HelperAttestationDigest != value.Decision.HelperAttestationDigest ||
		value.Audit.PolicyDecisionDigest != value.Decision.PolicyDecisionDigest ||
		value.Audit.AuditReservationDigest != value.Decision.AuditReservationDigest {
		return unavailable("retained_result_invalid", nil)
	}
	return nil
}

func validationProvenance(request HelperRequest, response HelperResponse, attestation string) string {
	return digestValue("COH-KUSTO-VALIDATION-PROVENANCE-V1\x00", struct{ Request, Response, Attestation string }{
		request.RequestDigest, response.ResponseDigest, attestation})
}

func admissionCheck(phase string, input ValidateRequest, request HelperRequest, response, attestation string, now time.Time) AdmissionCheck {
	return AdmissionCheck{Phase: phase, Query: input.Query, Capability: input.Capability,
		HelperRequestDigest: request.RequestDigest, HelperResponseDigest: response, SchemaDigest: request.SchemaDigest,
		RegistryDigest: input.Registry.Digest, HelperAttestationDigest: attestation,
		QualificationDigest: input.QualificationDigest, EvaluatedAt: now}
}

func sortedReasons(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}

func cloneAdmission(value ValidationAdmission) ValidationAdmission {
	value.Validation.ReasonCodes = slices.Clone(value.Validation.ReasonCodes)
	value.OutputColumns = slices.Clone(value.OutputColumns)
	value.Decision.ReasonCodes = slices.Clone(value.Decision.ReasonCodes)
	value.Audit.ReasonCodes = slices.Clone(value.Audit.ReasonCodes)
	return value
}
