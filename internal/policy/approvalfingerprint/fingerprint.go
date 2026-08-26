package approvalfingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func (engine *Engine) Build(ctx context.Context, manifest actionmanifest.VerifiedEnvelope, authority actionmanifest.SignerAuthority, decision policy.Decision) (Fingerprint, error) {
	return engine.perform(ctx, "build", Fingerprint{}, manifest, authority, decision)
}

func (engine *Engine) Verify(ctx context.Context, candidate Fingerprint, manifest actionmanifest.VerifiedEnvelope, authority actionmanifest.SignerAuthority, decision policy.Decision) (Fingerprint, error) {
	return engine.perform(ctx, "verify", candidate, manifest, authority, decision)
}

func (engine *Engine) perform(ctx context.Context, operation string, candidate Fingerprint, manifest actionmanifest.VerifiedEnvelope, authority actionmanifest.SignerAuthority, decision policy.Decision) (Fingerprint, error) {
	now := time.Time{}
	if engine != nil && engine.clock != nil {
		now = engine.clock.Now().UTC()
	}
	if engine == nil || engine.audit == nil || engine.clock == nil {
		return Fingerprint{}, policy.NewError(policy.Unavailable, "fingerprint_unavailable")
	}
	var result Fingerprint
	resultErr := contextError(ctx)
	if resultErr == nil && now.IsZero() {
		resultErr = policy.NewError(policy.Unavailable, "clock_unavailable")
	}
	if resultErr == nil && operation == "verify" {
		resultErr = validateFingerprint(candidate)
	}
	if resultErr == nil {
		fresh, err := actionmanifest.Verify(ctx, manifest.CanonicalEnvelopeBytes(), authority)
		if err != nil || fresh.ManifestDigest != manifest.ManifestDigest {
			resultErr = policy.NewError(policy.Denied, "manifest_authority")
		} else {
			result, resultErr = derive(fresh, decision, now)
		}
	}
	if resultErr == nil && operation == "verify" && !sameFingerprint(candidate, result) {
		resultErr = policy.NewError(policy.Denied, "fingerprint_mismatch")
	}
	event := auditEvent(operation, result, resultErr, now, manifest, decision)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := engine.audit.AppendApprovalFingerprintEvent(auditCtx, event); err != nil {
		return Fingerprint{}, policy.NewError(policy.Unavailable, "audit_unavailable")
	}
	if resultErr != nil {
		return Fingerprint{}, resultErr
	}
	return result, nil
}

func derive(verified actionmanifest.VerifiedEnvelope, decision policy.Decision, now time.Time) (Fingerprint, error) {
	manifest := verified.Manifest()
	manifestBytes := verified.CanonicalManifestBytes()
	if len(manifestBytes) == 0 || !digestPattern.MatchString(verified.ManifestDigest) {
		return Fingerprint{}, policy.NewError(policy.InvalidInput, "manifest_binding")
	}
	if err := validatePolicyDecision(decision, manifest, verified.ManifestDigest, now); err != nil {
		return Fingerprint{}, err
	}
	decisionBytes, err := policy.VerifyDecisionDigest(decision)
	if err != nil {
		return Fingerprint{}, err
	}
	validFrom, _ := time.Parse(timestampLayout, manifest.ValidFrom)
	validUntil, _ := time.Parse(timestampLayout, manifest.ValidUntil)
	if now.Before(validFrom) || !now.Before(validUntil) {
		return Fingerprint{}, policy.NewError(policy.Denied, "manifest_not_current")
	}
	digest := fingerprintDigest(manifestBytes, decisionBytes)
	return Fingerprint{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, FingerprintDigest: digest,
		ManifestDigest: verified.ManifestDigest, PolicyDecisionDigest: decision.DecisionDigest,
		OrganizationID: manifest.OrganizationID, TenantID: manifest.TenantID, CaseID: manifest.CaseID,
		RequestorActorID: manifest.RequestorActorID, ActionOwnerActorID: manifest.ActionOwnerActorID,
		PolicyDigest: manifest.PolicyDigest, PolicyRevision: manifest.PolicyRevision, ROEDigest: cloneString(manifest.ROEDigest),
		ValidFrom: manifest.ValidFrom, ValidUntil: manifest.ValidUntil, MaximumUseCount: manifest.MaximumUseCount,
	}, nil
}

func validatePolicyDecision(decision policy.Decision, manifest actionmanifest.Manifest, manifestDigest string, now time.Time) error {
	if decision.SchemaVersion != policy.SchemaVersion || decision.ContractVersion != policy.ContractVersion ||
		!uuidPattern.MatchString(decision.EvaluationID) || !uuidPattern.MatchString(decision.BundleID) ||
		!uuidPattern.MatchString(decision.ActorID) || decision.ActorRevision == 0 ||
		!digestPattern.MatchString(decision.DecisionDigest) || !digestPattern.MatchString(decision.InputDigest) ||
		!digestPattern.MatchString(decision.ManifestDigest) || !digestPattern.MatchString(decision.PolicyDigest) ||
		!tokenPattern.MatchString(decision.ReasonCode) || !tokenPattern.MatchString(decision.SignerKeyID) ||
		decision.SignerKeyRevision == 0 {
		return policy.NewError(policy.InvalidInput, "policy_decision_contract")
	}
	if decision.Outcome != "allowed" {
		return policy.NewError(policy.Denied, "policy_not_allowed")
	}
	if decision.Phase != policy.IntentCreated {
		return policy.NewError(policy.Denied, "policy_phase")
	}
	if !decision.ApprovalRequired {
		return policy.NewError(policy.Denied, "approval_not_required")
	}
	if decision.ManifestDigest != manifestDigest {
		return policy.NewError(policy.Denied, "manifest_binding")
	}
	if decision.PolicyDigest != manifest.PolicyDigest || decision.PolicyRevision != manifest.PolicyRevision {
		return policy.NewError(policy.Denied, "policy_binding")
	}
	if decision.ActorID != manifest.RequestorActorID {
		return policy.NewError(policy.Denied, "actor_binding")
	}
	evaluatedAt, err := time.Parse(timestampLayout, decision.EvaluatedAt)
	from, fromErr := time.Parse(timestampLayout, manifest.ValidFrom)
	until, untilErr := time.Parse(timestampLayout, manifest.ValidUntil)
	if err != nil || fromErr != nil || untilErr != nil || evaluatedAt.Before(from) ||
		!evaluatedAt.Before(until) || evaluatedAt.After(now) {
		return policy.NewError(policy.Denied, "policy_time")
	}
	return nil
}

func fingerprintDigest(manifestBytes, decisionBytes []byte) string {
	var preimage bytes.Buffer
	preimage.WriteString(HashDomain)
	_ = binary.Write(&preimage, binary.BigEndian, uint64(len(manifestBytes)))
	preimage.Write(manifestBytes)
	_ = binary.Write(&preimage, binary.BigEndian, uint64(len(decisionBytes)))
	preimage.Write(decisionBytes)
	sum := sha256.Sum256(preimage.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameFingerprint(left, right Fingerprint) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	leftCanonical, leftErr := domaincontract.Canonicalize(leftBytes)
	rightCanonical, rightErr := domaincontract.Canonicalize(rightBytes)
	return leftErr == nil && rightErr == nil &&
		subtle.ConstantTimeCompare(leftCanonical, rightCanonical) == 1
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return policy.NewError(policy.InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return policy.NewError(policy.Timeout, "request_timeout")
		}
		return policy.NewError(policy.Canceled, "request_canceled")
	}
	return nil
}

func auditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
}

func auditEvent(operation string, result Fingerprint, resultErr error, now time.Time, verified actionmanifest.VerifiedEnvelope, decision policy.Decision) AuditEvent {
	outcome, reason := "allowed", "fingerprint_built"
	if operation == "verify" {
		reason = "fingerprint_verified"
	}
	if resultErr != nil {
		outcome, reason = "denied", policy.Reason(resultErr)
		switch policy.Code(resultErr) {
		case policy.InvalidInput:
			outcome = "invalid"
		case policy.Canceled:
			outcome = "canceled"
		case policy.Timeout:
			outcome = "timeout"
		case policy.Unavailable:
			outcome = "unavailable"
		}
	}
	manifest := verified.Manifest()
	occurredAt := decision.EvaluatedAt
	if occurredAt == "" {
		occurredAt = now.Format(timestampLayout)
	}
	event := AuditEvent{Operation: operation, Outcome: outcome, ReasonCode: reason,
		FingerprintDigest: result.FingerprintDigest, ManifestDigest: result.ManifestDigest,
		PolicyDecisionDigest: result.PolicyDecisionDigest, OccurredAt: occurredAt,
		OrganizationID: manifest.OrganizationID, TenantID: manifest.TenantID, CaseID: manifest.CaseID,
		ActorID: decision.ActorID, ActorRevision: decision.ActorRevision}
	event.EventID = auditEventDigest(event)
	return event
}

func auditEventDigest(event AuditEvent) string {
	event.EventID = ""
	encoded, _ := json.Marshal(event)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
