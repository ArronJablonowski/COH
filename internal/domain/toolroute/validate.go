package toolroute

import (
	"regexp"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

var (
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	mediaPattern  = regexp.MustCompile(`^[a-z][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$`)
)

func ValidateIntent(value domain.ToolIntent) error {
	if !uuidV7Pattern.MatchString(value.OperationID) || !validCase(value.Case) ||
		!tokenPattern.MatchString(value.Tool) || !tokenPattern.MatchString(value.Action) ||
		!digestPattern.MatchString(value.TargetDigest) || !digestPattern.MatchString(value.ArgumentDigest) {
		return newError(InvalidInput, "intent_invalid", nil)
	}
	return nil
}

func ValidateIntentRecord(value IntentRecord) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Denied, "intent_contract_unsupported", nil)
	}
	return ValidateIntent(value.Domain())
}

func ValidateReceipt(value domain.ActionReceipt, intentDigest string) error {
	if !digestPattern.MatchString(intentDigest) || value.IntentDigest != intentDigest ||
		!digestPattern.MatchString(value.Evidence.Digest) || !mediaPattern.MatchString(value.Evidence.MediaType) ||
		!tokenPattern.MatchString(value.Evidence.Classification) || value.Evidence.Length < 0 {
		return newError(Denied, "receipt_binding_invalid", nil)
	}
	switch value.Outcome {
	case "succeeded", "denied", "canceled", "timeout", "failed", "uncertain":
		return nil
	default:
		return newError(Denied, "receipt_outcome_invalid", nil)
	}
}

func ValidateReceiptRecord(value ReceiptRecord) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Denied, "receipt_contract_unsupported", nil)
	}
	return ValidateReceipt(value.Domain(), value.IntentDigest)
}

func ValidateStateRecord(value StateRecord) error {
	if value.SchemaVersion != SchemaVersion || value.ContractVersion != ContractVersion || value.RecordType != "state" ||
		!uuidV7Pattern.MatchString(value.OperationID) || !uuidV7Pattern.MatchString(value.OrganizationID) ||
		!uuidV7Pattern.MatchString(value.TenantID) || !uuidV7Pattern.MatchString(value.CaseID) ||
		!digestPattern.MatchString(value.IntentDigest) || !digestPattern.MatchString(value.IdempotencyDigest) ||
		!digestPattern.MatchString(value.ContextDigest) || !digestPattern.MatchString(value.ManifestDigest) ||
		!digestPattern.MatchString(value.IntentPolicyDecisionDigest) || !uuidV7Pattern.MatchString(value.ApprovalID) ||
		!uuidV7Pattern.MatchString(value.RequestorActorID) || value.RequestorActorRevision == 0 ||
		!uuidV7Pattern.MatchString(value.ActionOwnerActorID) || value.ActionOwnerActorRevision == 0 ||
		!validStateStatus(value.Status) || !tokenPattern.MatchString(value.ReasonCode) ||
		!digestPattern.MatchString(value.ProvenanceDigest) || value.Revision == 0 {
		return newError(Denied, "state_record_invalid", nil)
	}
	for _, optional := range []string{value.PreDispatchDecisionDigest, value.ApprovalFingerprintDigest,
		value.DispatchAuditID, value.CompletionAuditID, value.ReceiptDigest, value.PreviousProvenanceDigest} {
		if optional != "" && !digestPattern.MatchString(optional) {
			return newError(Denied, "state_digest_invalid", nil)
		}
	}
	authorized := value.PreDispatchDecisionDigest != "" || value.ApprovalRevision != 0 ||
		value.ApprovalFingerprintDigest != ""
	if authorized && (value.PreDispatchDecisionDigest == "" || value.ApprovalRevision == 0 ||
		value.ApprovalFingerprintDigest == "") {
		return newError(Denied, "state_authority_invalid", nil)
	}
	terminal := terminalStateStatus(value.Status)
	if terminal != (value.CompletionAuditID != "") || terminal != (value.ReceiptDigest != "") ||
		value.Status == "dispatching" && value.DispatchAuditID == "" ||
		(value.Status == "succeeded" || value.Status == "uncertain") && value.DispatchAuditID == "" {
		return newError(Denied, "state_terminal_binding_invalid", nil)
	}
	created, createdErr := time.Parse(timestampLayout, value.CreatedAt)
	updated, updatedErr := time.Parse(timestampLayout, value.UpdatedAt)
	if createdErr != nil || updatedErr != nil || updated.Before(created) ||
		created.Format(timestampLayout) != value.CreatedAt || updated.Format(timestampLayout) != value.UpdatedAt {
		return newError(Denied, "state_timestamp_invalid", nil)
	}
	return nil
}

func validStateStatus(value string) bool {
	return value == "pending" || value == "authorizing" || value == "dispatching" || terminalStateStatus(value)
}

func terminalStateStatus(value string) bool {
	return value == "succeeded" || value == "denied" || value == "canceled" || value == "timeout" ||
		value == "failed" || value == "uncertain"
}

func validCase(value domain.CaseRef) bool {
	return uuidV7Pattern.MatchString(value.OrganizationID) && uuidV7Pattern.MatchString(value.TenantID) &&
		uuidV7Pattern.MatchString(value.CaseID)
}
