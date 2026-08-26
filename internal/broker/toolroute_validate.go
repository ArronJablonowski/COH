package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	toolRouteContextDomain    = "COH-TOOL-ROUTE-CONTEXT-V1\x00"
	toolRouteProvenanceDomain = "COH-TOOL-ROUTE-PROVENANCE-V1\x00"
	toolRouteReceiptDomain    = "COH-TOOL-ROUTE-RECEIPT-V1\x00"
)

func newToolRouteRecord(intent domain.ToolIntent, intentDigest, idempotencyDigest, contextDigest string,
	verified actionmanifest.VerifiedEnvelope, command preDispatchCommand, now time.Time) (toolRouteRecord, error) {
	record := toolRouteRecord{RecordVersion: toolRouteRecordVersion, OperationID: intent.OperationID,
		Case: intent.Case, IntentDigest: intentDigest, IdempotencyDigest: idempotencyDigest, ContextDigest: contextDigest,
		ManifestDigest: verified.ManifestDigest, IntentPolicyDecisionDigest: command.IntentDecision.DecisionDigest,
		ApprovalID: command.Approval.ApprovalID, RequestorActorID: command.PolicyActor.ActorID,
		RequestorActorRevision: command.PolicyActor.Revision, ActionOwnerActorID: command.Approval.Actor.ActorID,
		ActionOwnerActorRevision: command.Approval.Actor.Revision, Status: routePending, ReasonCode: "route_started",
		CreatedAt: now, UpdatedAt: now, Revision: 1}
	provenance, err := toolRouteProvenance("", "route_started", record)
	if err != nil {
		return toolRouteRecord{}, err
	}
	record.ProvenanceDigest = provenance
	return record, validateToolRouteRecord(record)
}

func validateToolRouteRecord(value toolRouteRecord) error {
	if value.RecordVersion != toolRouteRecordVersion || !uuidPattern.MatchString(value.OperationID) ||
		!validRouteCase(value.Case) || !digestPattern.MatchString(value.IntentDigest) ||
		!digestPattern.MatchString(value.IdempotencyDigest) ||
		!digestPattern.MatchString(value.ContextDigest) || !digestPattern.MatchString(value.ManifestDigest) ||
		!digestPattern.MatchString(value.IntentPolicyDecisionDigest) || !uuidPattern.MatchString(value.ApprovalID) ||
		!uuidPattern.MatchString(value.RequestorActorID) || value.RequestorActorRevision == 0 ||
		!uuidPattern.MatchString(value.ActionOwnerActorID) || value.ActionOwnerActorRevision == 0 ||
		!digestPattern.MatchString(value.ProvenanceDigest) || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() ||
		value.CreatedAt.Location() != time.UTC || value.UpdatedAt.Location() != time.UTC ||
		value.UpdatedAt.Before(value.CreatedAt) || value.Revision == 0 || !tokenPattern.MatchString(value.ReasonCode) {
		return newRouteError(routeCodeDenied, "route_record_invalid", false, nil)
	}
	if value.PreDispatchDecisionDigest != "" && !digestPattern.MatchString(value.PreDispatchDecisionDigest) ||
		value.ApprovalFingerprintDigest != "" && !digestPattern.MatchString(value.ApprovalFingerprintDigest) ||
		value.DispatchAuditID != "" && !digestPattern.MatchString(value.DispatchAuditID) ||
		value.CompletionAuditID != "" && !digestPattern.MatchString(value.CompletionAuditID) ||
		value.ReceiptDigest != "" && !digestPattern.MatchString(value.ReceiptDigest) ||
		value.PreviousProvenanceDigest != "" && !digestPattern.MatchString(value.PreviousProvenanceDigest) {
		return newRouteError(routeCodeDenied, "route_record_digest_invalid", false, nil)
	}
	authorized := value.PreDispatchDecisionDigest != "" || value.ApprovalRevision != 0 ||
		value.ApprovalFingerprintDigest != ""
	if authorized && (value.PreDispatchDecisionDigest == "" || value.ApprovalRevision == 0 ||
		value.ApprovalFingerprintDigest == "") {
		return newRouteError(routeCodeDenied, "route_record_authority_invalid", false, nil)
	}
	if !validToolRouteStatus(value.Status) {
		return newRouteError(routeCodeDenied, "route_record_status_invalid", false, nil)
	}
	terminal := terminalToolRouteStatus(value.Status)
	if terminal != (value.ReceiptDigest != "") || terminal != (value.CompletionAuditID != "") ||
		terminal && toolroute.ValidateReceipt(value.Receipt, value.IntentDigest) != nil ||
		!terminal && value.Receipt != (domain.ActionReceipt{}) {
		return newRouteError(routeCodeDenied, "route_record_receipt_invalid", false, nil)
	}
	if value.Status == routeDispatching && value.DispatchAuditID == "" ||
		terminal && value.Status != routeDenied && value.DispatchAuditID == "" && value.Status != routeCanceled &&
			value.Status != routeTimeout && value.Status != routeFailed {
		return newRouteError(routeCodeDenied, "route_record_audit_invalid", false, nil)
	}
	if err := toolroute.ValidateStateRecord(toolRouteStateRecord(value)); err != nil {
		return newRouteError(routeCodeDenied, "route_state_contract_invalid", false, err)
	}
	expectedProvenance, err := toolRouteProvenance(value.PreviousProvenanceDigest, value.ReasonCode, value)
	if err != nil || expectedProvenance != value.ProvenanceDigest {
		return newRouteError(routeCodeDenied, "route_provenance_invalid", false, nil)
	}
	return nil
}

func validateToolRouteTransition(prior, next toolRouteRecord) error {
	if err := validateToolRouteRecord(prior); err != nil {
		return err
	}
	if err := validateToolRouteRecord(next); err != nil {
		return err
	}
	if prior.RecordVersion != next.RecordVersion || prior.OperationID != next.OperationID || prior.Case != next.Case ||
		prior.IntentDigest != next.IntentDigest || prior.IdempotencyDigest != next.IdempotencyDigest ||
		prior.ContextDigest != next.ContextDigest ||
		prior.ManifestDigest != next.ManifestDigest || prior.IntentPolicyDecisionDigest != next.IntentPolicyDecisionDigest ||
		prior.ApprovalID != next.ApprovalID || prior.RequestorActorID != next.RequestorActorID ||
		prior.RequestorActorRevision != next.RequestorActorRevision ||
		prior.ActionOwnerActorID != next.ActionOwnerActorID || prior.ActionOwnerActorRevision != next.ActionOwnerActorRevision ||
		prior.CreatedAt != next.CreatedAt || next.UpdatedAt.Before(prior.UpdatedAt) || next.Revision != prior.Revision+1 ||
		next.PreviousProvenanceDigest != prior.ProvenanceDigest ||
		prior.ProvenanceDigest == next.ProvenanceDigest || !legalToolRouteTransition(prior.Status, next.Status) {
		return newRouteError(routeCodeDenied, "route_transition_invalid", false, nil)
	}
	if prior.PreDispatchDecisionDigest != "" && prior.PreDispatchDecisionDigest != next.PreDispatchDecisionDigest ||
		prior.ApprovalRevision != 0 && prior.ApprovalRevision != next.ApprovalRevision ||
		prior.ApprovalFingerprintDigest != "" && prior.ApprovalFingerprintDigest != next.ApprovalFingerprintDigest ||
		prior.DispatchAuditID != "" && prior.DispatchAuditID != next.DispatchAuditID ||
		prior.CompletionAuditID != "" || prior.ReceiptDigest != "" || prior.Receipt != (domain.ActionReceipt{}) ||
		next.Status == routeAuthorizing && (next.PreDispatchDecisionDigest != "" || next.ApprovalRevision != 0 ||
			next.ApprovalFingerprintDigest != "" || next.DispatchAuditID != "") ||
		next.Status == routeDispatching && next.DispatchAuditID == "" ||
		terminalToolRouteStatus(next.Status) && (next.CompletionAuditID == "" || next.ReceiptDigest == "") {
		return newRouteError(routeCodeDenied, "route_transition_binding_invalid", false, nil)
	}
	return nil
}

func legalToolRouteTransition(prior, next toolRouteStatus) bool {
	switch prior {
	case routePending:
		return next == routeAuthorizing || terminalToolRouteStatus(next)
	case routeAuthorizing:
		return next == routeDispatching || terminalToolRouteStatus(next)
	case routeDispatching:
		return terminalToolRouteStatus(next)
	default:
		return false
	}
}

func validToolRouteStatus(value toolRouteStatus) bool {
	return value == routePending || value == routeAuthorizing || value == routeDispatching || terminalToolRouteStatus(value)
}

func terminalToolRouteStatus(value toolRouteStatus) bool {
	return value == routeSucceeded || value == routeDenied || value == routeCanceled || value == routeTimeout ||
		value == routeFailed || value == routeUncertain
}

func validateIntentManifestBinding(intent domain.ToolIntent, verified actionmanifest.VerifiedEnvelope) error {
	manifest := verified.Manifest()
	if manifest.WorkflowTaskID != intent.OperationID || manifest.OrganizationID != intent.Case.OrganizationID ||
		manifest.TenantID != intent.Case.TenantID || manifest.CaseID != intent.Case.CaseID ||
		manifest.Tool.Name != intent.Tool || manifest.Operation != intent.Action ||
		len(manifest.TargetDigests) != 1 || manifest.TargetDigests[0] != intent.TargetDigest ||
		manifest.ArgumentsDigest != intent.ArgumentDigest {
		return newRouteError(routeCodeDenied, "intent_manifest_binding", false, nil)
	}
	return nil
}

func validateRouteReplay(existing, candidate toolRouteRecord) error {
	if existing.OperationID != candidate.OperationID || existing.Case != candidate.Case ||
		existing.IntentDigest != candidate.IntentDigest || existing.IdempotencyDigest != candidate.IdempotencyDigest ||
		existing.ContextDigest != candidate.ContextDigest ||
		existing.ManifestDigest != candidate.ManifestDigest ||
		existing.IntentPolicyDecisionDigest != candidate.IntentPolicyDecisionDigest ||
		existing.ApprovalID != candidate.ApprovalID || existing.RequestorActorID != candidate.RequestorActorID ||
		existing.RequestorActorRevision != candidate.RequestorActorRevision ||
		existing.ActionOwnerActorID != candidate.ActionOwnerActorID ||
		existing.ActionOwnerActorRevision != candidate.ActionOwnerActorRevision {
		return newRouteError(routeCodeDenied, "route_replay_binding", false, nil)
	}
	return validateToolRouteRecord(existing)
}

func toolRouteContextDigest(command preDispatchCommand) (string, error) {
	encoded, err := json.Marshal(command)
	if err != nil {
		return "", newRouteError(routeCodeUnavailable, "route_context_encoding", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newRouteError(routeCodeDenied, "route_context_invalid", false, nil)
	}
	return routeDigest(toolRouteContextDomain, canonical), nil
}

func toolRouteProvenance(prior, operation string, value toolRouteRecord) (string, error) {
	copy := value
	copy.ProvenanceDigest = ""
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", newRouteError(routeCodeUnavailable, "route_provenance_encoding", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newRouteError(routeCodeDenied, "route_provenance_invalid", false, nil)
	}
	return routeDigest(toolRouteProvenanceDomain, bytes.Join([][]byte{[]byte(prior), []byte(operation), canonical}, []byte{0})), nil
}

func toolRouteReceiptDigest(value domain.ActionReceipt) (string, error) {
	record := toolroute.ReceiptFromDomain(value)
	canonical, err := toolroute.CanonicalReceipt(record)
	if err != nil {
		return "", newRouteError(routeCodeDenied, "route_receipt_invalid", true, nil)
	}
	return routeDigest(toolRouteReceiptDomain, canonical), nil
}

func routeDigest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validRouteCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func routeEvidence(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if digestPattern.MatchString(value) {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func toolRouteStateRecord(value toolRouteRecord) toolroute.StateRecord {
	return toolroute.StateRecord{SchemaVersion: toolroute.SchemaVersion, ContractVersion: toolroute.ContractVersion,
		RecordType: "state", OperationID: value.OperationID, OrganizationID: value.Case.OrganizationID,
		TenantID: value.Case.TenantID, CaseID: value.Case.CaseID, IntentDigest: value.IntentDigest,
		IdempotencyDigest: value.IdempotencyDigest, ContextDigest: value.ContextDigest,
		ManifestDigest: value.ManifestDigest, IntentPolicyDecisionDigest: value.IntentPolicyDecisionDigest,
		PreDispatchDecisionDigest: value.PreDispatchDecisionDigest, ApprovalID: value.ApprovalID,
		ApprovalRevision: value.ApprovalRevision, ApprovalFingerprintDigest: value.ApprovalFingerprintDigest,
		RequestorActorID: value.RequestorActorID, RequestorActorRevision: value.RequestorActorRevision,
		ActionOwnerActorID: value.ActionOwnerActorID, ActionOwnerActorRevision: value.ActionOwnerActorRevision,
		Status: string(value.Status), ReasonCode: value.ReasonCode, DispatchAuditID: value.DispatchAuditID,
		CompletionAuditID: value.CompletionAuditID, ReceiptDigest: value.ReceiptDigest,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: formatTime(value.CreatedAt),
		UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision}
}
