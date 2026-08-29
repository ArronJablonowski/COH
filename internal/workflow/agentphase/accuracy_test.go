package agentphase

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskContractAndPromptBindQualifiedCapabilities(t *testing.T) {
	contract := testTaskContract(t)
	profile := testExecutionProfile()
	prompt, err := CompilePrompt(contract, profile)
	if err != nil {
		t.Fatal(err)
	}
	if prompt.TaskContractDigest != contract.Digest() || prompt.ExecutionProfileDigest != profile.Digest() ||
		!strings.Contains(prompt.SystemPrompt, "untrusted data") || !strings.Contains(prompt.UserPrompt, contract.Workspace) {
		t.Fatalf("compiled prompt lost contract bindings: %+v", prompt)
	}
	profile.ToolCalls = false
	profile.MaximumParallelToolCall = 0
	if _, err = CompilePrompt(contract, profile); err == nil {
		t.Fatal("missing qualified tool support was accepted")
	}
}

func TestTaskContractRejectsUnsafeOrUnboundedValues(t *testing.T) {
	contract := testTaskContract(t)
	contract.Repair.MaximumModelCalls = 4
	if err := contract.Validate(); err == nil {
		t.Fatal("four model calls were accepted")
	}
	contract = testTaskContract(t)
	contract.AllowedTools = []string{"write_file", "read_file"}
	if err := contract.Validate(); err == nil {
		t.Fatal("unsorted tools were accepted")
	}
	contract = testTaskContract(t)
	contract.Workspace += string(filepath.Separator) + ".."
	if err := contract.Validate(); err == nil {
		t.Fatal("unclean workspace was accepted")
	}
}

func TestRepairControllerUsesThreeBoundedModelProducedAttempts(t *testing.T) {
	contract := testTaskContract(t)
	generator := &generatorStub{}
	validator := &validatorStub{acceptOn: 3}
	controller, err := NewRepairController(generator, validator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := controller.Run(context.Background(), contract, testExecutionProfile())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Calls != 3 || len(result.Validations) != 3 || generator.calls != 3 {
		t.Fatalf("unexpected repair result: %+v calls=%d", result, generator.calls)
	}
	if result.Validations[1].PreviousProvenanceDigest != result.Validations[0].ProvenanceDigest ||
		result.Validations[2].PreviousProvenanceDigest != result.Validations[1].ProvenanceDigest {
		t.Fatal("validation provenance chain was not bound")
	}
	if !strings.Contains(generator.requests[1].UserPrompt, "mandatory_check") {
		t.Fatal("repair did not receive deterministic diagnostics")
	}
}

func TestRepairControllerFailsClosedAndNeverRepeatsSideEffects(t *testing.T) {
	contract := testTaskContract(t)
	contract.SecuritySensitive = true
	controller, _ := NewRepairController(&generatorStub{}, &validatorStub{acceptOn: 9})
	result, err := controller.Run(context.Background(), contract, testExecutionProfile())
	if err != nil || result.Accepted || result.Incomplete || result.Calls != 3 {
		t.Fatalf("security-sensitive exhaustion did not fail closed: %+v err=%v", result, err)
	}
	generator := &generatorStub{sideEffect: SideEffectUncertain}
	controller, _ = NewRepairController(generator, &validatorStub{acceptOn: 2})
	if _, err = controller.Run(context.Background(), contract, testExecutionProfile()); err == nil || generator.calls != 1 {
		t.Fatalf("uncertain side effect was retried: calls=%d err=%v", generator.calls, err)
	}
}

func TestValidatorRegistryRejectsFencesAndWorkspaceSymlinks(t *testing.T) {
	contract := testTaskContract(t)
	contract.AllowedTools = nil
	contract.RequiredCapabilities.ToolCalls = false
	contract.Output.Kind = OutputJSONSchema
	contract.Output.Name = "answer"
	contract.Output.SchemaDigest = canonicalDigest("schema")
	contract.RequiredCapabilities.StructuredOutput = true
	contract.ValidatorProfile = "json-v1"
	validator, err := NewValidatorRegistry().Resolve(contract.ValidatorProfile)
	if err != nil {
		t.Fatal(err)
	}
	candidate := CandidateArtifact{ArtifactDigest: canonicalDigest("candidate"), Text: "```json\n{\"ok\":true}\n```", Workspace: contract.Workspace}
	record, err := validator.Validate(context.Background(), contract, candidate, 1, canonicalDigest("budget"), "")
	if err != nil || record.Disposition != ValidationRevise {
		t.Fatalf("fenced JSON was accepted: %+v err=%v", record, err)
	}
	candidate.Text = `{"ok":true}`
	record, err = validator.Validate(context.Background(), contract, candidate, 1, canonicalDigest("budget"), "")
	if err != nil || record.Disposition != ValidationAccepted {
		t.Fatalf("raw JSON was not accepted: %+v err=%v", record, err)
	}
	if err = os.Symlink("/tmp", filepath.Join(contract.Workspace, "escape")); err != nil {
		t.Fatal(err)
	}
	record, err = validator.Validate(context.Background(), contract, candidate, 1, canonicalDigest("budget"), "")
	if err != nil || record.Disposition != ValidationRevise || record.Checks[0].Passed {
		t.Fatalf("workspace symlink was not rejected: %+v err=%v", record, err)
	}
}

type generatorStub struct {
	calls      uint32
	sideEffect SideEffectState
	requests   []GenerationRequest
}

func (generator *generatorStub) Generate(_ context.Context, request GenerationRequest) (CandidateArtifact, string, error) {
	generator.calls++
	generator.requests = append(generator.requests, request)
	sideEffect := generator.sideEffect
	if sideEffect == "" {
		sideEffect = SideEffectNone
	}
	return CandidateArtifact{ArtifactDigest: canonicalDigest(struct{ Attempt uint32 }{request.Attempt}),
		Text: "candidate", Workspace: request.Contract.Workspace, SideEffect: sideEffect}, canonicalDigest(struct{ Budget uint32 }{request.Attempt}), nil
}

type validatorStub struct{ acceptOn uint32 }

func (validator *validatorStub) ID() string     { return "workspace-v1" }
func (validator *validatorStub) Digest() string { return canonicalDigest("validator") }
func (validator *validatorStub) Validate(_ context.Context, _ TaskContract, candidate CandidateArtifact,
	attempt uint32, budget, previous string) (ValidationRecordV2, error) {
	passed := attempt >= validator.acceptOn
	checks := []ValidationCheck{{Code: "mandatory_check", Mandatory: true, Passed: passed,
		EvidenceRefs: []string{candidate.ArtifactDigest}}}
	diagnostics := []ValidationDiagnostic{}
	if !passed {
		diagnostics = append(diagnostics, ValidationDiagnostic{Code: "mandatory_check", Message: "Correct the requested artifact.",
			EvidenceRefs: []string{candidate.ArtifactDigest}})
	}
	return NewValidationRecord(attempt, candidate.ArtifactDigest, validator.ID(), validator.Digest(), budget, previous, checks, diagnostics)
}

func testTaskContract(t *testing.T) TaskContract {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	return TaskContract{ContractVersion: TaskContractVersion, ContractID: "cyber-task",
		Objective:            "Repair the supplied fixture and verify the result.",
		Output:               OutputContract{Kind: OutputWorkspace, Instructions: []string{"Create the requested implementation.", "Verify the result before finishing."}, ExampleDigests: []string{}},
		RequiredCapabilities: CapabilityRequirements{Text: true, ToolCalls: true},
		AllowedTools:         []string{"read_file", "write_file"}, SafetyBoundary: "Do not access anything outside the workspace.",
		Workspace: workspace, ValidatorProfile: "workspace-v1", Repair: RepairPolicy{MaximumModelCalls: 3}}
}

func testExecutionProfile() ModelExecutionProfile {
	return ModelExecutionProfile{ContractVersion: ExecutionProfileVersion, ProfileID: "ollama-local",
		ModelDigest: canonicalDigest("model"), CapabilityDigest: canonicalDigest("capability"),
		QualificationDigest: canonicalDigest("qualification"), SystemPrompt: "You are COH, a precise cybersecurity agent.",
		MessageRole: "system", ReasoningMode: ReasoningDisabled, Text: true, StructuredOutput: true, ToolCalls: true,
		MaximumInputTokens: 32768, MaximumOutputTokens: 8192, MaximumParallelToolCall: 1}
}
