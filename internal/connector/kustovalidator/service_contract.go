package kustovalidator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func projectHelperRequest(ctx context.Context, input ValidateRequest, now time.Time) (HelperRequest, error) {
	queryBytes, err := json.Marshal(input.Query)
	if err != nil {
		return HelperRequest{}, queryconnector.NewError(queryconnector.InvalidInput, "query_invalid", err)
	}
	validatedQuery, err := queryconnector.DecodeQuery(ctx, queryBytes)
	if err != nil {
		return HelperRequest{}, err
	}
	capabilityBytes, err := json.Marshal(input.Capability)
	if err != nil {
		return HelperRequest{}, queryconnector.NewError(queryconnector.InvalidInput, "capability_invalid", err)
	}
	validatedCapability, err := queryconnector.DecodeCapability(ctx, capabilityBytes)
	if err != nil {
		return HelperRequest{}, err
	}
	if validatedCapability.Digest() != input.Query.CapabilityDigest || input.Capability.SourceID != input.Query.Scope.SourceID ||
		!input.Capability.Features.Validation || input.Query.Language != "kql" {
		return HelperRequest{}, queryconnector.NewError(queryconnector.Denied, "capability_binding_denied", nil)
	}
	capabilityExpiry, ok := parseBoundaryTimestamp(input.Capability.ValidUntil)
	deadline, deadlineOK := parseBoundaryTimestamp(input.Query.Deadline)
	if !ok || !deadlineOK || !capabilityExpiry.After(now) || !deadline.After(now) {
		return HelperRequest{}, queryconnector.NewError(queryconnector.Denied, "validation_deadline_or_capability_stale", nil)
	}
	if validateSchema(input.Schema) != nil || !schemaFresh(input.Schema, now) || validateRegistry(input.Registry) != nil ||
		validatePolicy(input.Policy) != nil || validateAttestation(input.Helper) != nil || input.Policy.RegistryDigest != input.Registry.Digest ||
		input.Helper.Identity.RegistryDigest != input.Registry.Digest || !validDigests(input.WorkspaceIdentityDigest, input.QualificationDigest) ||
		!tokenPattern.MatchString(input.IdempotencyKey) || validatedQuery.Digest() == "" {
		return HelperRequest{}, queryconnector.NewError(queryconnector.InvalidInput, "validator_request_invalid", nil)
	}
	rows := min(input.Query.Limits.MaximumRows, input.Policy.MaximumRows, input.Capability.HardLimits.MaximumRows)
	request := HelperRequest{SchemaVersion: HelperRequestVersion, ContractVersion: ContractVersion,
		RequestID: input.Query.QueryID, Operation: "kusto.validate", Query: input.Query.NativeText,
		QueryDigest: QueryDigest(input.Query.NativeText), SourceID: input.Query.Scope.SourceID,
		ResourceIDs: input.Query.Scope.ResourceIDs, WorkspaceIdentityDigest: input.WorkspaceIdentityDigest,
		QualificationDigest: input.QualificationDigest, CapabilityDigest: input.Query.CapabilityDigest,
		Schema: input.Schema, SchemaDigest: SchemaDigest(input.Schema), Policy: input.Policy,
		HelperIdentityExpectation: input.Helper.Identity, RequestedRows: rows, Deadline: input.Query.Deadline}
	request.Deadline = deadline.Format(time.RFC3339Nano)
	request.RequestDigest = HelperRequestDigest(request)
	if validateHelperRequest(request) != nil {
		return HelperRequest{}, queryconnector.NewError(queryconnector.InvalidInput, "helper_projection_invalid", nil)
	}
	return request, nil
}

func schemaFresh(schema SchemaBinding, now time.Time) bool {
	observed, observedOK := parseTimestamp(schema.ObservedAt)
	validUntil, validOK := parseTimestamp(schema.ValidUntil)
	return observedOK && validOK && !observed.After(now) && validUntil.After(now)
}

func buildDecision(input ValidateRequest, request HelperRequest, response HelperResponse, attestation string, now time.Time) PolicyDecision {
	deadline, _ := parseBoundaryTimestamp(input.Query.Deadline)
	validUntil := now.Add(5 * time.Minute)
	if deadline.Before(validUntil) {
		validUntil = deadline
	}
	value := PolicyDecision{SchemaVersion: PolicyDecisionVersion, ContractVersion: ContractVersion,
		DecisionID: input.Query.QueryID, QueryID: input.Query.QueryID, Outcome: response.Outcome,
		ReasonCodes: sortedReasons(response.ReasonCodes), ActorID: input.Query.Authority.ActorID,
		ScopeDigest: scopeDigest(input.Query.Scope), RequestDigest: request.RequestDigest,
		ResponseDigest: response.ResponseDigest, CapabilityDigest: input.Query.CapabilityDigest,
		SchemaDigest: request.SchemaDigest, RegistryDigest: input.Registry.Digest,
		HelperAttestationDigest: attestation, PolicyDecisionDigest: input.Query.Authority.PolicyDecisionDigest,
		AuditReservationDigest: input.Query.Authority.AuditReservationDigest,
		ObservedAt:             now.Format(time.RFC3339Nano), ValidUntil: validUntil.Format(time.RFC3339Nano)}
	value.Digest = PolicyDecisionDigest(value)
	return value
}

func buildAudit(input ValidateRequest, decision PolicyDecision, response HelperResponse) AuditProof {
	return AuditProof{SchemaVersion: AuditProofVersion, ContractVersion: ContractVersion, Event: "kusto.validation",
		Outcome: response.Outcome, ReasonCodes: sortedReasons(response.ReasonCodes), QueryID: input.Query.QueryID,
		ActorID: input.Query.Authority.ActorID, ScopeDigest: decision.ScopeDigest, RequestDigest: decision.RequestDigest,
		ResponseDigest: response.ResponseDigest, RegistryDigest: input.Registry.Digest,
		HelperAttestationDigest: decision.HelperAttestationDigest,
		PolicyDecisionDigest:    input.Query.Authority.PolicyDecisionDigest,
		AuditReservationDigest:  input.Query.Authority.AuditReservationDigest,
		AuditRecordDigest:       digestValue("COH-KUSTO-AUDIT-REQUEST-V1\x00", decision)}
}

func validateCommittedAudit(request, proof AuditProof) error {
	if validateAudit(proof) != nil || proof.SchemaVersion != request.SchemaVersion || proof.ContractVersion != request.ContractVersion ||
		proof.Event != request.Event || proof.Outcome != request.Outcome || proof.QueryID != request.QueryID ||
		proof.ActorID != request.ActorID || proof.ScopeDigest != request.ScopeDigest || proof.RequestDigest != request.RequestDigest ||
		proof.ResponseDigest != request.ResponseDigest || proof.RegistryDigest != request.RegistryDigest ||
		proof.HelperAttestationDigest != request.HelperAttestationDigest || proof.PolicyDecisionDigest != request.PolicyDecisionDigest ||
		proof.AuditReservationDigest != request.AuditReservationDigest {
		return denied()
	}
	return nil
}

func scopeDigest(scope queryconnector.Scope) string {
	return digestValue("COH-KUSTO-SCOPE-V1\x00", scope)
}

func parseBoundaryTimestamp(value string) (time.Time, bool) {
	if parsed, ok := parseTimestamp(value); ok {
		return parsed, true
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return parsed, err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == value
}
