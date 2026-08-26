package agentphase

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

func TestCanonicalPhaseRecordsRoundTripAndRejectUnknownDuplicateOrTrailingData(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	input, err := fixture.coordinator.Input(session)
	if err != nil {
		t.Fatal(err)
	}
	encodedInput, err := CanonicalInput(input)
	if err != nil {
		t.Fatal(err)
	}
	decodedInput, err := DecodeInput(encodedInput)
	if err != nil || !reflect.DeepEqual(decodedInput, input) {
		t.Fatalf("decoded=%+v err=%v", decodedInput, err)
	}
	actionStep, _ := phaseStepID(testRun, testTrace, 1, ActPhase)
	intent := domain.ToolIntent{OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read", TargetDigest: testDigestOne, ArgumentDigest: testDigestSix}
	intentDigest, _ := agentloop.ToolIntentDigest(intent)
	output := planOutput(t, fixture, session, intentDigest)
	encodedOutput, err := CanonicalOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	decodedOutput, err := DecodeOutput(encodedOutput)
	if err != nil || !reflect.DeepEqual(decodedOutput, output) {
		t.Fatalf("decoded=%+v err=%v", decodedOutput, err)
	}
	unknown := append(append([]byte{}, encodedOutput[:len(encodedOutput)-1]...), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(encodedOutput, []byte(`"contract_version":"coh.agent-phase/v1"`), []byte(`"contract_version":"coh.agent-phase/v1","contract_version":"coh.agent-phase/v1"`), 1)
	missingRequired := bytes.Replace(encodedOutput, []byte(`"negative_result":false,`), nil, 1)
	for name, malformed := range map[string][]byte{
		"unknown":          unknown,
		"duplicate":        duplicate,
		"missing_required": missingRequired,
		"trailing":         append(append([]byte{}, encodedOutput...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeOutput(malformed); Code(err) != Denied {
				t.Fatalf("malformed record accepted: %s err=%v", malformed, err)
			}
		})
	}
}

func TestDecodeRejectsMissingNestedRequiredFieldEvenWhenZeroWouldBeValid(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := advanceToReview(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	encoded, err := CanonicalOutput(reviewOutput(t, fixture, session, ReviewAccepted))
	if err != nil {
		t.Fatal(err)
	}
	missingConfidence := bytes.Replace(encoded, []byte(`"confidence_basis_points":8500,`), nil, 1)
	if _, err := DecodeOutput(missingConfidence); Code(err) != Denied || Reason(err) != "record_required_field_missing" {
		t.Fatalf("missing nested required field accepted: %s err=%v", missingConfidence, err)
	}
}

func TestPublishedPhaseFixturesDecode(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/agent-phase-input.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInput(input); err != nil {
		t.Fatalf("input fixture: %v", err)
	}
	output, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/agent-phase-review-output.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOutput(output); err != nil {
		t.Fatalf("output fixture: %v", err)
	}
}

func TestReviewRequiresOrderedEvidenceBearingClaimsAndFindings(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := advanceToReview(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	valid := reviewOutput(t, fixture, session, ReviewAccepted)
	if err := validatePhaseOutput(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Findings = append([]Finding{}, valid.Findings...)
	invalid.Findings[0].EvidenceRefs = []string{}
	if err := validatePhaseOutput(invalid); Code(err) != Denied {
		t.Fatalf("evidenceless finding accepted: %v", err)
	}
	invalid = valid
	invalid.Claims = append([]Claim{}, valid.Claims...)
	invalid.Claims[0].RecommendedNextStepDigests = nil
	if err := validatePhaseOutput(invalid); Code(err) != Denied {
		t.Fatalf("claim without explicit next steps accepted: %v", err)
	}
	if fixture.action.calls != 1 {
		t.Fatalf("unexpected action calls=%d", fixture.action.calls)
	}
}
