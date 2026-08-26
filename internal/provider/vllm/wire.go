package vllm

import "encoding/json"

type versionResponse struct {
	Version string `json:"version"`
}

type modelsResponse struct {
	Object string        `json:"object"`
	Data   []modelRecord `json:"data"`
}
type modelRecord struct {
	ID                 string            `json:"id"`
	Object             string            `json:"object"`
	Created            int64             `json:"created"`
	OwnedBy            string            `json:"owned_by"`
	Root               *string           `json:"root"`
	Parent             *string           `json:"parent"`
	MaximumModelLength *uint64           `json:"max_model_len"`
	Permission         []modelPermission `json:"permission"`
}
type modelPermission struct {
	ID                 string  `json:"id"`
	Object             string  `json:"object"`
	Created            int64   `json:"created"`
	AllowCreateEngine  bool    `json:"allow_create_engine"`
	AllowSampling      bool    `json:"allow_sampling"`
	AllowLogprobs      bool    `json:"allow_logprobs"`
	AllowSearchIndices bool    `json:"allow_search_indices"`
	AllowView          bool    `json:"allow_view"`
	AllowFineTuning    bool    `json:"allow_fine_tuning"`
	Organization       string  `json:"organization"`
	Group              *string `json:"group"`
	IsBlocking         bool    `json:"is_blocking"`
}

// tokenizer_info intentionally retains the entire provider object. Its
// canonical digest binds all init kwargs, while the named fields are extracted
// from the same exact object after duplicate-key validation.
type tokenizerInfo map[string]json.RawMessage

type chatRequest struct {
	Model                   string          `json:"model"`
	Messages                []chatMessage   `json:"messages"`
	Tools                   []functionTool  `json:"tools,omitempty"`
	ToolChoice              string          `json:"tool_choice"`
	ParallelToolCalls       bool            `json:"parallel_tool_calls"`
	ResponseFormat          *responseFormat `json:"response_format,omitempty"`
	MaximumCompletionTokens uint64          `json:"max_completion_tokens"`
	Temperature             float64         `json:"temperature"`
	TopP                    float64         `json:"top_p"`
	Seed                    uint32          `json:"seed"`
	N                       uint8           `json:"n"`
	Logprobs                bool            `json:"logprobs"`
	IncludeReasoning        bool            `json:"include_reasoning"`
	Stream                  bool            `json:"stream"`
	StreamOptions           *streamOptions  `json:"stream_options,omitempty"`
}
type streamOptions struct {
	IncludeUsage         bool `json:"include_usage"`
	ContinuousUsageStats bool `json:"continuous_usage_stats"`
}
type responseFormat struct {
	Type       string          `json:"type"`
	JSONSchema namedJSONSchema `json:"json_schema"`
}
type namedJSONSchema struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

type chatMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	Reasoning  string           `json:"reasoning,omitempty"`
	ToolCalls  []nativeToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}
type functionTool struct {
	Type     string         `json:"type"`
	Function toolDefinition `json:"function"`
}
type toolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Strict      bool            `json:"strict"`
}
type nativeToolCall struct {
	Index    *uint64        `json:"index,omitempty"`
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function nativeFunction `json:"function"`
}
type nativeFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatResponse struct {
	ID                string          `json:"id"`
	Object            string          `json:"object"`
	Created           int64           `json:"created"`
	Model             string          `json:"model"`
	Choices           []chatChoice    `json:"choices"`
	ServiceTier       json.RawMessage `json:"service_tier"`
	SystemFingerprint *string         `json:"system_fingerprint"`
	Usage             usage           `json:"usage"`
	PromptLogprobs    json.RawMessage `json:"prompt_logprobs"`
	PromptTokenIDs    json.RawMessage `json:"prompt_token_ids"`
	PromptText        json.RawMessage `json:"prompt_text"`
	KVTransferParams  json.RawMessage `json:"kv_transfer_params"`
	ECTransferParams  json.RawMessage `json:"ec_transfer_params"`
	Metrics           json.RawMessage `json:"metrics"`
}
type chatChoice struct {
	Index         uint64          `json:"index"`
	Message       responseMessage `json:"message"`
	Logprobs      json.RawMessage `json:"logprobs"`
	FinishReason  *string         `json:"finish_reason"`
	StopReason    json.RawMessage `json:"stop_reason"`
	TokenIDs      json.RawMessage `json:"token_ids"`
	RoutedExperts json.RawMessage `json:"routed_experts"`
}
type responseMessage struct {
	Role         string           `json:"role"`
	Content      *string          `json:"content"`
	Refusal      json.RawMessage  `json:"refusal"`
	Annotations  json.RawMessage  `json:"annotations"`
	Audio        json.RawMessage  `json:"audio"`
	FunctionCall json.RawMessage  `json:"function_call"`
	ToolCalls    []nativeToolCall `json:"tool_calls,omitempty"`
	Reasoning    *string          `json:"reasoning"`
}
type usage struct {
	PromptTokens            uint64                  `json:"prompt_tokens"`
	TotalTokens             uint64                  `json:"total_tokens"`
	CompletionTokens        *uint64                 `json:"completion_tokens"`
	PromptTokensDetails     *promptTokenDetails     `json:"prompt_tokens_details"`
	CompletionTokensDetails *completionTokenDetails `json:"completion_tokens_details"`
}
type promptTokenDetails struct {
	CachedTokens       *uint64         `json:"cached_tokens"`
	CreatedCacheTokens *uint64         `json:"created_cache_tokens"`
	MultimodalTokens   json.RawMessage `json:"multimodal_tokens"`
}
type completionTokenDetails struct {
	ReasoningTokens uint64 `json:"reasoning_tokens"`
}

type streamChunk struct {
	ID                string          `json:"id"`
	Object            string          `json:"object"`
	Created           int64           `json:"created"`
	Model             string          `json:"model"`
	Choices           []streamChoice  `json:"choices"`
	Usage             *usage          `json:"usage,omitempty"`
	SystemFingerprint *string         `json:"system_fingerprint,omitempty"`
	PromptTokenIDs    json.RawMessage `json:"prompt_token_ids,omitempty"`
	PromptText        json.RawMessage `json:"prompt_text,omitempty"`
	Metrics           json.RawMessage `json:"metrics,omitempty"`
}
type streamChoice struct {
	Index        uint64          `json:"index"`
	Delta        streamDelta     `json:"delta"`
	Logprobs     json.RawMessage `json:"logprobs,omitempty"`
	FinishReason *string         `json:"finish_reason,omitempty"`
	StopReason   json.RawMessage `json:"stop_reason,omitempty"`
	TokenIDs     json.RawMessage `json:"token_ids,omitempty"`
}
type streamDelta struct {
	Role      string           `json:"role,omitempty"`
	Content   *string          `json:"content,omitempty"`
	Refusal   json.RawMessage  `json:"refusal,omitempty"`
	ToolCalls []nativeToolCall `json:"tool_calls,omitempty"`
	Reasoning *string          `json:"reasoning,omitempty"`
}
