package redaction

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type bindingFixture struct {
	rule          RuleSet
	plan          ApprovedPlan
	command       Command
	approval      ApprovalUseProof
	authorization AuthorizationRequest
	decision      Decision
	mapping       Mapping
	record        Record
	receipt       Receipt
}

func TestCanonicalBindingsValidateCompleteFixture(t *testing.T) {
	fixture := newBindingFixture(t)
	golden := map[string][2]string{
		"rule":          {fixture.rule.RuleDigest, "sha256:456b181f15b06f1a6657a6154149abd2423e8767f6ff36d127122040ccbbe7be"},
		"plan":          {fixture.plan.PlanDigest, "sha256:bcf241ba60e0ed878f3e2896d70d1cdfe445858a01c43a4363b07a094f227cdc"},
		"intent":        {fixture.authorization.IntentDigest, "sha256:97cdf057df63069f138e4558d5db4d4f5afa270655523210f607247cffcbe5e3"},
		"approval":      {fixture.approval.ProofDigest, "sha256:e5ed62afae9db07a6fffff5c7072c67020bdb5ba24182f02017f5c49de87843d"},
		"authorization": {fixture.authorization.AuthorizationDigest, "sha256:e8a536b91bfe85a413d803bc86f50ffd13d50997e85c614a882b56ff4640443e"},
		"decision":      {fixture.decision.DecisionDigest, "sha256:07151dc82b3bf6940ef589141e20194d728df79e2518f910e748068ebf79e225"},
		"mapping":       {fixture.mapping.MappingDigest, "sha256:be82f5c5788b434c4d03a28655e761371422066a34b04321bfc4feaa22c50311"},
		"record":        {fixture.record.RecordDigest, "sha256:6d883bd7de77ba00f9b8214ed3d35d22ad4c5394c9b006e7bb10b7c3684bcade"},
		"receipt":       {fixture.receipt.ReceiptDigest, "sha256:7f3fafd8d7c99e20f0b027c5d4f0695dcfef2f5952f75fda6cdadc49bc47c5fc"},
	}
	for name, pair := range golden {
		if pair[0] != pair[1] {
			t.Fatalf("%s digest=%s want=%s", name, pair[0], pair[1])
		}
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"command", func() error { return ValidateCommand(fixture.command, fixture.command.Deadline.Add(-time.Second)) }},
		{"rule", func() error { return ValidateRule(fixture.rule) }},
		{"plan", func() error { return ValidatePlan(fixture.plan) }},
		{"approval", func() error { return ValidateApprovalUse(fixture.approval) }},
		{"authorization", func() error { return ValidateAuthorization(fixture.authorization) }},
		{"decision", func() error { return ValidateDecision(fixture.decision) }},
		{"mapping", func() error { return ValidateMapping(fixture.mapping) }},
		{"record", func() error { return ValidateRecord(fixture.record) }},
		{"receipt", func() error { return ValidateReceipt(fixture.receipt) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err != nil {
				t.Fatal(err)
			}
		})
	}
	canonical, err := CanonicalCommand(fixture.command)
	if err != nil || !bytes.Contains(canonical, []byte(`"expected_custody_head":{"case":{"case_id"`)) {
		t.Fatalf("custody case missing from canonical command: %s err=%v", canonical, err)
	}
}

func TestCanonicalBindingsRejectSecurityRelevantMutation(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*bindingFixture)
		validate func(bindingFixture) error
	}{
		{"tenant", func(v *bindingFixture) { v.authorization.Command.Case.TenantID = testID(90) }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"actor revision", func(v *bindingFixture) { v.authorization.Command.ActorRevision++ }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"source", func(v *bindingFixture) { v.authorization.Command.Source.Artifact.Digest = testDigest("1") }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"rule", func(v *bindingFixture) { v.plan.RuleDigest = testDigest("2") }, func(v bindingFixture) error { return ValidatePlan(v.plan) }},
		{"plan", func(v *bindingFixture) { v.authorization.Command.PlanDigest = testDigest("3") }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"approval", func(v *bindingFixture) { v.approval.UseCount = 2 }, func(v bindingFixture) error { return ValidateApprovalUse(v.approval) }},
		{"authorization policy", func(v *bindingFixture) { v.authorization.Plan.PolicyDigest = testDigest("4") }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"classification", func(v *bindingFixture) { v.authorization.Command.OutputClassification = "internal" }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"custody", func(v *bindingFixture) { v.authorization.CurrentCustodyHead.ChainHash = testDigest("5") }, func(v bindingFixture) error { return ValidateAuthorization(v.authorization) }},
		{"revocation", func(v *bindingFixture) { v.decision.RevocationDigest = testDigest("6") }, func(v bindingFixture) error { return ValidateDecision(v.decision) }},
		{"mapping", func(v *bindingFixture) { v.mapping.Entries[0].ReplacementDigest = testDigest("7") }, func(v bindingFixture) error { return ValidateMapping(v.mapping) }},
		{"audit", func(v *bindingFixture) { v.record.AuditEventDigest = testDigest("8") }, func(v bindingFixture) error { return ValidateRecord(v.record) }},
		{"provenance", func(v *bindingFixture) { v.record.PreviousProvenanceDigest = testDigest("9") }, func(v bindingFixture) error { return ValidateRecord(v.record) }},
		{"receipt", func(v *bindingFixture) { v.receipt.RecordDigest = testDigest("a") }, func(v bindingFixture) error { return ValidateReceipt(v.receipt) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := newBindingFixture(t)
			test.mutate(&changed)
			if err := test.validate(changed); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestBindingOperationsDoNotMutateCallerOwnedSlices(t *testing.T) {
	fixture := newBindingFixture(t)
	media := append([]string(nil), fixture.rule.AllowedMediaTypes...)
	modes := append([]ReplacementMode(nil), fixture.rule.PermittedModes...)
	spans := append([]PlanSpan(nil), fixture.plan.Spans...)
	entries := append([]MappingEntry(nil), fixture.mapping.Entries...)
	if _, err := RuleBindingDigest(fixture.rule); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanBindingDigest(fixture.plan); err != nil {
		t.Fatal(err)
	}
	if _, err := MappingBindingDigest(fixture.mapping); err != nil {
		t.Fatal(err)
	}
	if !equalStrings(media, fixture.rule.AllowedMediaTypes) || !equalModes(modes, fixture.rule.PermittedModes) ||
		!equalSpans(spans, fixture.plan.Spans) || !equalEntries(entries, fixture.mapping.Entries) {
		t.Fatal("binding mutated caller input")
	}
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	caseRef := domain.CaseRef{OrganizationID: testID(1), TenantID: testID(2), CaseID: testID(3)}
	source := testEvidence(testDigest("a"), "text/plain", "restricted", 100, "b", "c", "d")
	head := CustodyHead{Case: caseRef, ChainHash: genesisHash}
	rule := RuleSet{SchemaVersion: RuleSetSchemaVersion, ContractVersion: ContractVersion, RuleID: testID(4), Revision: 1,
		AllowedMediaTypes: []string{"text/plain"}, PermittedModes: []ReplacementMode{Mask, Remove}, MaximumSpans: 8,
		MaximumSelectedBytes: 50, MaximumOutputBytes: 100, SignerKeyID: "redaction-key", SignerKeyRevision: 1,
		Signature: strings.Repeat("A", 86)}
	rule.RuleDigest = mustDigest(t, func() (string, error) { return RuleBindingDigest(rule) })
	plan := ApprovedPlan{SchemaVersion: PlanSchemaVersion, ContractVersion: ContractVersion, PlanID: testID(5), Case: caseRef,
		Source: source, RuleID: rule.RuleID, RuleRevision: rule.Revision, RuleDigest: rule.RuleDigest, ReasonDigest: testDigest("e"),
		Spans: []PlanSpan{{Ordinal: 1, SourceStart: 10, SourceEnd: 20, SourceSegmentDigest: testDigest("1"), ReplacementMode: Remove, ExpectedOutputStart: 10, ExpectedOutputEnd: 10},
			{Ordinal: 2, SourceStart: 30, SourceEnd: 35, SourceSegmentDigest: testDigest("2"), ReplacementMode: Mask, ExpectedOutputStart: 20, ExpectedOutputEnd: 25}},
		OutputMediaType: "text/plain", OutputClassification: "confidential", MaximumOutputBytes: 100,
		ApprovalID: testID(6), ApprovalFingerprintDigest: testDigest("3"), ApprovalManifestDigest: testDigest("4"),
		PolicyDecisionDigest: testDigest("5"), PolicyDigest: testDigest("6"), ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	plan.MappingPlanDigest = mustDigest(t, func() (string, error) { return MappingPlanBindingDigest(plan) })
	plan.PlanDigest = mustDigest(t, func() (string, error) { return PlanBindingDigest(plan) })
	command := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion, RequestID: testID(7),
		IdempotencyKey: "redact-0001", Case: caseRef, ActorID: testID(8), ActorRevision: 4, Source: source,
		RuleDigest: rule.RuleDigest, PlanDigest: plan.PlanDigest, ReasonDigest: plan.ReasonDigest, OutputMediaType: plan.OutputMediaType,
		OutputClassification: plan.OutputClassification, KeyProfile: "case-evidence", KeyProfileDigest: testDigest("7"),
		PolicyDigest: plan.PolicyDigest, ExpectedCaseRevision: 9, ExpectedCustodyHead: head, Deadline: at.Add(30 * time.Minute)}
	intent := mustDigest(t, func() (string, error) { return IntentBindingDigest(command) })
	approval := ApprovalUseProof{ApprovalID: plan.ApprovalID, FingerprintDigest: plan.ApprovalFingerprintDigest,
		ManifestDigest: plan.ApprovalManifestDigest, PolicyDecisionDigest: plan.PolicyDecisionDigest, IntentDigest: intent,
		State: "consumed", Revision: 2, UseCount: 1, MaximumUseCount: 1, ValidFrom: plan.ValidFrom, ValidUntil: plan.ValidUntil,
		UseDigest: testDigest("8"), UsedAt: at}
	approval.ProofDigest = mustDigest(t, func() (string, error) { return ApprovalUseBindingDigest(approval) })
	auth := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion, IntentDigest: intent,
		Command: command, Plan: plan, CaseState: "open", CaseClassification: "restricted", CaseRevision: 9,
		CaseProvenanceDigest: testDigest("9"), SourceVerificationDigest: testDigest("a"), ApprovalUse: approval, CurrentCustodyHead: head}
	auth.AuthorizationDigest = mustDigest(t, func() (string, error) { return AuthorizationBindingDigest(auth) })
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion, DecisionID: testID(9),
		AuthorizationDigest: auth.AuthorizationDigest, IntentDigest: intent, Case: caseRef, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, SourceArtifactDigest: source.Artifact.Digest, PlanDigest: plan.PlanDigest,
		ApprovalFingerprintDigest: approval.FingerprintDigest, PolicyDigest: plan.PolicyDigest, RevocationDigest: testDigest("b"),
		ExpectedCaseRevision: command.ExpectedCaseRevision, ExpectedCustodyHead: head, Outcome: Allow,
		ReasonCode: ReasonAuthorized, IssuedAt: at, ExpiresAt: at.Add(20 * time.Minute), Revision: 1}
	decision.DecisionDigest = mustDigest(t, func() (string, error) { return DecisionBindingDigest(decision) })
	derivedArtifact := domain.ArtifactRef{Digest: testDigest("c"), MediaType: "text/plain", Classification: "confidential", Length: 90}
	mapping := Mapping{SchemaVersion: MappingSchemaVersion, ContractVersion: ContractVersion, MappingID: testID(10), Case: caseRef,
		Source: source, DerivedArtifact: derivedArtifact, PlanDigest: plan.PlanDigest, RuleDigest: rule.RuleDigest,
		ReasonDigest: plan.ReasonDigest, ApprovalFingerprintDigest: approval.FingerprintDigest,
		Entries: []MappingEntry{{Ordinal: 1, SourceStart: 10, SourceEnd: 20, SourceSegmentDigest: testDigest("1"), OutputStart: 10, OutputEnd: 10, ReplacementMode: Remove, ReplacementDigest: testDigest("d")},
			{Ordinal: 2, SourceStart: 30, SourceEnd: 35, SourceSegmentDigest: testDigest("2"), OutputStart: 20, OutputEnd: 25, ReplacementMode: Mask, ReplacementDigest: testDigest("e")}},
		CreatedAt: at, PreviousProvenanceDigest: testDigest("f")}
	mapping.ProvenanceDigest = mustDigest(t, func() (string, error) { return MappingProvenanceDigest(mapping) })
	mapping.MappingDigest = mustDigest(t, func() (string, error) { return MappingBindingDigest(mapping) })
	derived := testEvidence(derivedArtifact.Digest, derivedArtifact.MediaType, derivedArtifact.Classification, 90, "d", "e", "f")
	mappingRef := testEvidence(testDigest("0"), mappingMediaType, "confidential", 512, "1", "2", "3")
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, RedactionID: testID(11), Case: caseRef,
		Command: command, IntentDigest: intent, PlanDigest: plan.PlanDigest, DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, ApprovalUseDigest: approval.UseDigest, SourceVerificationDigest: auth.SourceVerificationDigest,
		Derived: derived, DerivedIngestionReceiptDigest: derived.IngestionReceiptDigest, MappingReference: mappingRef,
		MappingDigest: mapping.MappingDigest, MappingIngestionReceiptDigest: mappingRef.IngestionReceiptDigest,
		CustodyReceiptDigest: testDigest("4"), CreatedAt: at, PreviousProvenanceDigest: testDigest("5")}
	record.ProvenanceDigest = mustDigest(t, func() (string, error) { return RecordProvenanceDigest(record) })
	record.AuditEventDigest = testDigest("6")
	record.RecordDigest = mustDigest(t, func() (string, error) { return RecordBindingDigest(record) })
	idempotency := mustDigest(t, func() (string, error) { return IdempotencyBindingDigest(command.IdempotencyKey) })
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion, RequestID: command.RequestID,
		Case: caseRef, IdempotencyDigest: idempotency, IntentDigest: intent, RedactionID: record.RedactionID,
		RecordDigest: record.RecordDigest, Derived: derived, MappingReference: mappingRef, MappingDigest: mapping.MappingDigest,
		CustodyReceiptDigest: record.CustodyReceiptDigest, AuditEventDigest: record.AuditEventDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: at}
	receipt.ReceiptDigest = mustDigest(t, func() (string, error) { return ReceiptBindingDigest(receipt) })
	return bindingFixture{rule, plan, command, approval, auth, decision, mapping, record, receipt}
}

func testEvidence(digestValue, media, classification string, length int64, manifest, provenance, receipt string) EvidenceReference {
	return EvidenceReference{Artifact: domain.ArtifactRef{Digest: digestValue, MediaType: media, Classification: classification, Length: length},
		Manifest:                 domain.ArtifactRef{Digest: testDigest(manifest), MediaType: manifestMediaType, Classification: classification, Length: 256},
		ManifestProvenanceDigest: testDigest(provenance), IngestionReceiptDigest: testDigest(receipt)}
}

func testID(value int) string        { return fmt.Sprintf("00000000-0000-7000-8000-%012d", value) }
func testDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }
func mustDigest(t *testing.T, function func() (string, error)) string {
	t.Helper()
	value, err := function()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func equalStrings(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }
func equalModes(a, b []ReplacementMode) bool {
	return len(a) == len(b) && func() bool {
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}()
}
func equalSpans(a, b []PlanSpan) bool {
	return len(a) == len(b) && func() bool {
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}()
}
func equalEntries(a, b []MappingEntry) bool {
	return len(a) == len(b) && func() bool {
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}()
}
