package openairesponses

import "encoding/json"

type createRequest struct {
	Model             string            `json:"model"`
	Input             []json.RawMessage `json:"input"`
	Tools             []functionTool    `json:"tools,omitempty"`
	ToolChoice        string            `json:"tool_choice,omitempty"`
	ParallelToolCalls bool              `json:"parallel_tool_calls"`
	Text              *textConfig       `json:"text,omitempty"`
	Temperature       float64           `json:"temperature"`
	TopP              float64           `json:"top_p"`
	MaxOutputTokens   uint64            `json:"max_output_tokens"`
	Include           []string          `json:"include"`
	Store             bool              `json:"store"`
	Background        bool              `json:"background"`
	Truncation        string            `json:"truncation"`
	Stream            bool              `json:"stream"`
}

type functionTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      bool            `json:"strict"`
}

type textConfig struct {
	Format jsonSchemaFormat `json:"format"`
}

type jsonSchemaFormat struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Schema json.RawMessage `json:"schema"`
	Strict bool            `json:"strict"`
}

type inputMessage struct {
	Type    string         `json:"type"`
	Role    string         `json:"role"`
	Content []inputContent `json:"content"`
}

type inputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type inputFunctionCall struct {
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type inputFunctionOutput struct {
	Type   string `json:"type"`
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

type functionOutputEnvelope struct {
	Outcome string          `json:"outcome"`
	Value   json.RawMessage `json:"value"`
}

type createResponse struct {
	ID                   string            `json:"id"`
	Object               string            `json:"object"`
	CreatedAt            int64             `json:"created_at"`
	Status               string            `json:"status"`
	Background           bool              `json:"background"`
	CompletedAt          *int64            `json:"completed_at"`
	Error                *vendorError      `json:"error"`
	IncompleteDetails    *incomplete       `json:"incomplete_details"`
	Instructions         json.RawMessage   `json:"instructions"`
	Input                []json.RawMessage `json:"input"`
	MaxOutputTokens      *uint64           `json:"max_output_tokens"`
	MaxToolCalls         *uint64           `json:"max_tool_calls"`
	Model                string            `json:"model"`
	Output               []json.RawMessage `json:"output"`
	ParallelToolCalls    bool              `json:"parallel_tool_calls"`
	PreviousResponseID   *string           `json:"previous_response_id"`
	Prompt               json.RawMessage   `json:"prompt"`
	PromptCacheKey       *string           `json:"prompt_cache_key"`
	PromptCacheOptions   json.RawMessage   `json:"prompt_cache_options"`
	PromptCacheRetention *string           `json:"prompt_cache_retention"`
	Reasoning            json.RawMessage   `json:"reasoning"`
	ReasoningEffort      *string           `json:"reasoning_effort"`
	SafetyIdentifier     *string           `json:"safety_identifier"`
	ServiceTier          string            `json:"service_tier"`
	Store                bool              `json:"store"`
	Temperature          *float64          `json:"temperature"`
	Text                 json.RawMessage   `json:"text"`
	ToolChoice           json.RawMessage   `json:"tool_choice"`
	Tools                []json.RawMessage `json:"tools"`
	TopLogprobs          *uint64           `json:"top_logprobs"`
	TopP                 *float64          `json:"top_p"`
	Truncation           string            `json:"truncation"`
	Usage                *vendorUsage      `json:"usage"`
	User                 *string           `json:"user"`
	Metadata             map[string]string `json:"metadata"`
	Moderation           json.RawMessage   `json:"moderation"`
	ContextManagement    []json.RawMessage `json:"context_management"`
	StreamOptions        json.RawMessage   `json:"stream_options"`
}

type vendorUsage struct {
	InputTokens        uint64             `json:"input_tokens"`
	OutputTokens       uint64             `json:"output_tokens"`
	TotalTokens        uint64             `json:"total_tokens"`
	InputTokenDetails  *inputTokenDetails `json:"input_tokens_details"`
	OutputTokenDetails *outputTokenDetail `json:"output_tokens_details"`
}

type inputTokenDetails struct {
	CachedTokens uint64 `json:"cached_tokens"`
}

type outputTokenDetail struct {
	ReasoningTokens uint64 `json:"reasoning_tokens"`
}

type vendorError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
	Param   string `json:"param"`
}

type incomplete struct {
	Reason string `json:"reason"`
}

type outputMessage struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`
	Role    string            `json:"role"`
	Status  string            `json:"status"`
	Content []json.RawMessage `json:"content"`
}

type outputText struct {
	Type        string            `json:"type"`
	Text        string            `json:"text"`
	Annotations []json.RawMessage `json:"annotations"`
}

type refusal struct {
	Type    string `json:"type"`
	Refusal string `json:"refusal"`
}

type functionCall struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Status    string `json:"status"`
}

type reasoningItem struct {
	ID               string             `json:"id"`
	Type             string             `json:"type"`
	Status           string             `json:"status"`
	EncryptedContent string             `json:"encrypted_content"`
	Summary          []reasoningSummary `json:"summary"`
}

type reasoningSummary struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
