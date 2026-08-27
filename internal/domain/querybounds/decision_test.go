package querybounds

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestDecisionCanonicalDigestDetectsTamper(t *testing.T) {
	decision := fixtureDecision()
	finalized, err := FinalizeDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := VerifyDecision(finalized)
	if err != nil || !bytes.Contains(canonical, []byte(`"reason_code":"bounds_satisfied"`)) {
		t.Fatalf("canonical decision err=%v", err)
	}
	changed := finalized
	changed.Outcome = "denied"
	if _, err := VerifyDecision(changed); Code(err) != Denied || Reason(err) != "decision_digest" {
		t.Fatalf("tamper accepted err=%v", err)
	}
	again, err := FinalizeDecision(decision)
	if err != nil || again.DecisionDigest != finalized.DecisionDigest {
		t.Fatalf("nondeterministic decision err=%v", err)
	}
}

func TestDecisionHasOnlyRedactedAuditFields(t *testing.T) {
	typeOf := reflect.TypeOf(Decision{})
	for index := 0; index < typeOf.NumField(); index++ {
		field := strings.Split(typeOf.Field(index).Tag.Get("json"), ",")[0]
		for _, forbidden := range []string{"native_text", "query_text", "rows", "credential", "secret", "handle", "vendor_error", "url", "headers"} {
			if field == forbidden {
				t.Fatalf("decision exposes %s", field)
			}
		}
	}
}

func fixtureDecision() Decision {
	return Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		QueryID: "0198e300-1000-7000-8000-000000000001", QueryDigest: digest("1"),
		Outcome: "allowed", ReasonCode: "bounds_satisfied",
		OrganizationID: "0198e300-1000-7000-8000-000000000002",
		TenantID:       "0198e300-1000-7000-8000-000000000003", CaseID: "0198e300-1000-7000-8000-000000000004",
		ActorID: "0198e300-1000-7000-8000-000000000005", ActorRevision: 1,
		SourceID: "sentinel-prod", SourceRevision: 1, AllowlistRevision: 1,
		CapabilityDigest: digest("2"), CapabilityRevision: 1, AuthorityDigest: digest("3"), ResourceScopeDigest: digest("4"),
		AuthorizationDecisionDigest: digest("5"), PolicyDecisionDigest: digest("6"), PolicyRevision: 1,
		ApprovalRequired: false, AuditReservationDigest: digest("7"), RevocationRevision: 1,
		IntervalStart: "2026-08-27T17:00:00.000000000Z", IntervalEnd: "2026-08-27T18:00:00.000000000Z",
		LimitsDigest: digest("8"), EvaluatedAt: "2026-08-27T18:00:01.000000000Z"}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
