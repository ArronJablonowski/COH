package agentphase

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

const (
	TaskContractVersion     = "coh.task-contract/v1"
	ExecutionProfileVersion = "coh.model-execution-profile/v1"
	ValidationRecordVersion = "coh.agent-phase/v2"
)

type OutputKind string

const (
	OutputText       OutputKind = "text"
	OutputJSONSchema OutputKind = "json_schema"
	OutputCode       OutputKind = "code"
	OutputSigma      OutputKind = "sigma"
	OutputSPL        OutputKind = "spl"
	OutputKQL        OutputKind = "kql"
	OutputESQL       OutputKind = "esql"
	OutputYARAL      OutputKind = "yaral"
	OutputWorkspace  OutputKind = "workspace"
)

type OutputContract struct {
	Kind           OutputKind `json:"kind"`
	Name           string     `json:"name,omitempty"`
	SchemaDigest   string     `json:"schema_digest,omitempty"`
	Instructions   []string   `json:"instructions"`
	ExampleDigests []string   `json:"example_digests"`
}

type CapabilityRequirements struct {
	Text             bool `json:"text"`
	Vision           bool `json:"vision"`
	ToolCalls        bool `json:"tool_calls"`
	StructuredOutput bool `json:"structured_output"`
}

type RepairPolicy struct {
	MaximumModelCalls uint32 `json:"maximum_model_calls"`
}

type TaskContract struct {
	ContractVersion      string                 `json:"contract_version"`
	ContractID           string                 `json:"contract_id"`
	Objective            string                 `json:"objective"`
	Output               OutputContract         `json:"output"`
	RequiredCapabilities CapabilityRequirements `json:"required_capabilities"`
	AllowedTools         []string               `json:"allowed_tools"`
	SafetyBoundary       string                 `json:"safety_boundary"`
	Workspace            string                 `json:"workspace"`
	ValidatorProfile     string                 `json:"validator_profile"`
	Repair               RepairPolicy           `json:"repair"`
	SecuritySensitive    bool                   `json:"security_sensitive"`
}

type ReasoningMode string

const (
	ReasoningDisabled ReasoningMode = "disabled"
	ReasoningEnabled  ReasoningMode = "enabled"
	ReasoningLow      ReasoningMode = "low"
	ReasoningMedium   ReasoningMode = "medium"
	ReasoningHigh     ReasoningMode = "high"
)

type ModelExecutionProfile struct {
	ContractVersion         string        `json:"contract_version"`
	ProfileID               string        `json:"profile_id"`
	ModelDigest             string        `json:"model_digest"`
	CapabilityDigest        string        `json:"capability_digest"`
	QualificationDigest     string        `json:"qualification_digest"`
	SystemPrompt            string        `json:"system_prompt"`
	PromptOverlay           string        `json:"prompt_overlay,omitempty"`
	MessageRole             string        `json:"message_role"`
	ReasoningMode           ReasoningMode `json:"reasoning_mode"`
	Text                    bool          `json:"text"`
	Vision                  bool          `json:"vision"`
	StructuredOutput        bool          `json:"structured_output"`
	ToolCalls               bool          `json:"tool_calls"`
	MaximumInputTokens      uint64        `json:"maximum_input_tokens"`
	MaximumOutputTokens     uint64        `json:"maximum_output_tokens"`
	MaximumParallelToolCall uint16        `json:"maximum_parallel_tool_calls"`
}

func (value TaskContract) Validate() error {
	if value.ContractVersion != TaskContractVersion || !validToken(value.ContractID) ||
		!boundedSafeText(value.Objective, 1, 1<<20) || !boundedSafeText(value.SafetyBoundary, 1, 1<<16) ||
		!validToken(value.ValidatorProfile) || value.Repair.MaximumModelCalls < 1 || value.Repair.MaximumModelCalls > 3 {
		return errors.New("task contract identity, text, validator, or repair policy is invalid")
	}
	if !filepath.IsAbs(value.Workspace) || filepath.Clean(value.Workspace) != value.Workspace {
		return errors.New("task contract workspace must be an absolute clean path")
	}
	if err := validateOutputContract(value.Output); err != nil {
		return err
	}
	if !slices.IsSorted(value.AllowedTools) || hasDuplicate(value.AllowedTools) {
		return errors.New("allowed tools must be sorted and unique")
	}
	for _, tool := range value.AllowedTools {
		if !validToken(tool) {
			return errors.New("allowed tool name is invalid")
		}
	}
	if !value.RequiredCapabilities.Vision && !value.RequiredCapabilities.Text ||
		value.RequiredCapabilities.ToolCalls != (len(value.AllowedTools) > 0) ||
		value.RequiredCapabilities.StructuredOutput != (value.Output.Kind == OutputJSONSchema) {
		return errors.New("task capability requirements do not match the output or tools")
	}
	return nil
}

func (value TaskContract) Digest() string { return canonicalDigest(value) }

func (value ModelExecutionProfile) Validate() error {
	if value.ContractVersion != ExecutionProfileVersion || !validToken(value.ProfileID) ||
		!validDigest(value.ModelDigest) || !validDigest(value.CapabilityDigest) ||
		!validDigest(value.QualificationDigest) || !boundedSafeText(value.SystemPrompt, 1, 1<<16) ||
		!boundedSafeText(value.PromptOverlay, 0, 1<<14) ||
		!slices.Contains([]string{"system", "developer"}, value.MessageRole) ||
		!slices.Contains([]ReasoningMode{ReasoningDisabled, ReasoningEnabled, ReasoningLow, ReasoningMedium, ReasoningHigh}, value.ReasoningMode) ||
		value.MaximumInputTokens == 0 || value.MaximumOutputTokens == 0 || !value.Text && !value.Vision {
		return errors.New("model execution profile is invalid")
	}
	if !value.ToolCalls && value.MaximumParallelToolCall != 0 || value.ToolCalls && value.MaximumParallelToolCall == 0 {
		return errors.New("model execution tool limits are inconsistent")
	}
	return nil
}

func (value ModelExecutionProfile) Digest() string { return canonicalDigest(value) }

func validateOutputContract(value OutputContract) error {
	if !slices.Contains([]OutputKind{OutputText, OutputJSONSchema, OutputCode, OutputSigma, OutputSPL, OutputKQL, OutputESQL, OutputYARAL, OutputWorkspace}, value.Kind) {
		return errors.New("output kind is unsupported")
	}
	if value.Kind == OutputJSONSchema {
		if !validToken(value.Name) || !validDigest(value.SchemaDigest) {
			return errors.New("structured output requires a name and schema digest")
		}
	} else if value.Name != "" || value.SchemaDigest != "" {
		return errors.New("non-schema output cannot bind a schema")
	}
	for _, instruction := range value.Instructions {
		if !boundedSafeText(instruction, 1, 4096) {
			return errors.New("output instruction is invalid")
		}
	}
	if len(value.Instructions) == 0 || !slices.IsSorted(value.ExampleDigests) || hasDuplicate(value.ExampleDigests) {
		return errors.New("output instructions or example digests are invalid")
	}
	for _, digest := range value.ExampleDigests {
		if !validDigest(digest) {
			return errors.New("output example digest is invalid")
		}
	}
	return nil
}

func canonicalDigest(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}

func boundedSafeText(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsRune(value, 0)
}

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}
