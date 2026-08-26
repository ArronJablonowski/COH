package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/policy"
)

const preDispatchAuditDomain = "COH-PRE-DISPATCH-AUDIT-V1\x00"

func preDispatchAuditEvent(manifest actionmanifest.Manifest, decision policy.Decision, approval lifecycle.Record,
	roe *verifiedROEProof, outcome, reason string) (tamperaudit.Event, error) {
	evidence := []string{decision.DecisionDigest, approval.FingerprintDigest, approval.ManifestDigest,
		approval.PolicyDecisionDigest}
	if roe != nil {
		evidence = append(evidence, roe.Digest)
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		OrganizationID: manifest.OrganizationID, TenantID: manifest.TenantID, CaseID: manifest.CaseID,
		ActorID: manifest.ActionOwnerActorID, ActorRevision: approval.LastActorRevision,
		SourceSchema: preDispatchSchemaVersion, Operation: "authorize", Outcome: outcome, ReasonCode: reason,
		SubjectID: manifest.ManifestID, SubjectRevision: approval.Revision, SubjectDigest: approval.ManifestDigest,
		EvidenceDigests: evidence, OccurredAt: decision.EvaluatedAt}
	encoded, err := json.Marshal(event)
	if err != nil {
		return tamperaudit.Event{}, err
	}
	sum := sha256.Sum256(append([]byte(preDispatchAuditDomain), encoded...))
	event.EventID = "sha256:" + hex.EncodeToString(sum[:])
	if err := tamperaudit.ValidateEvent(event); err != nil {
		return tamperaudit.Event{}, err
	}
	return event, nil
}
