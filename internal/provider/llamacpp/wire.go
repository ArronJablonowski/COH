package llamacpp

import "encoding/json"

type healthResponse struct {
	Status string `json:"status"`
}

type propertiesResponse struct {
	DefaultGenerationSettings json.RawMessage  `json:"default_generation_settings"`
	TotalSlots                uint16           `json:"total_slots"`
	ModelPath                 string           `json:"model_path"`
	ChatTemplate              string           `json:"chat_template"`
	ChatTemplateCaps          chatTemplateCaps `json:"chat_template_caps"`
	Modalities                modalities       `json:"modalities"`
	MediaMarker               string           `json:"media_marker"`
	BuildInfo                 string           `json:"build_info"`
	IsSleeping                bool             `json:"is_sleeping"`
}

type chatTemplateCaps struct {
	SupportsStringContent     bool `json:"supports_string_content"`
	SupportsTypedContent      bool `json:"supports_typed_content"`
	SupportsTools             bool `json:"supports_tools"`
	SupportsToolCalls         bool `json:"supports_tool_calls"`
	SupportsParallelToolCalls bool `json:"supports_parallel_tool_calls"`
	SupportsSystemRole        bool `json:"supports_system_role"`
	SupportsPreserveReasoning bool `json:"supports_preserve_reasoning"`
	SupportsReasoningEffort   bool `json:"supports_reasoning_effort"`
	SupportsObjectArguments   bool `json:"supports_object_arguments"`
}

type modalities struct {
	Vision bool `json:"vision"`
}

type modelsResponse struct {
	Object string        `json:"object"`
	Data   []modelRecord `json:"data"`
}

type modelRecord struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	OwnedBy string        `json:"owned_by"`
	Meta    modelMetadata `json:"meta"`
}

type modelMetadata struct {
	VocabularyType  uint64 `json:"vocab_type"`
	VocabularySize  uint64 `json:"n_vocab"`
	TrainingContext uint64 `json:"n_ctx_train"`
	EmbeddingSize   uint64 `json:"n_embd"`
	ParameterCount  uint64 `json:"n_params"`
	SizeBytes       uint64 `json:"size"`
}

type chatRequest struct {
	Model             string          `json:"model"`
	Messages          []chatMessage   `json:"messages"`
	Tools             []functionTool  `json:"tools,omitempty"`
	ToolChoice        string          `json:"tool_choice,omitempty"`
	ParallelToolCalls bool            `json:"parallel_tool_calls"`
	ResponseFormat    *responseFormat `json:"response_format,omitempty"`
	MaximumTokens     uint64          `json:"max_tokens"`
	Temperature       float64         `json:"temperature"`
	TopP              float64         `json:"top_p"`
	Seed              uint32          `json:"seed"`
	Stream            bool            `json:"stream"`
	StreamOptions     *streamOptions  `json:"stream_options,omitempty"`
	CachePrompt       bool            `json:"cache_prompt"`
	ParseToolCalls    bool            `json:"parse_tool_calls"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type responseFormat struct {
	Type   string          `json:"type"`
	Schema json.RawMessage `json:"schema"`
}

type chatMessage struct {
	Role             string           `json:"role"`
	Content          string           `json:"content,omitempty"`
	ReasoningContent string           `json:"reasoning_content,omitempty"`
	ToolCalls        []nativeToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string           `json:"tool_call_id,omitempty"`
}

type functionTool struct {
	Type     string         `json:"type"`
	Function toolDefinition `json:"function"`
}

type toolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
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
	ID                string       `json:"id"`
	Object            string       `json:"object"`
	Created           int64        `json:"created"`
	Model             string       `json:"model"`
	SystemFingerprint string       `json:"system_fingerprint"`
	Choices           []chatChoice `json:"choices"`
	Usage             usage        `json:"usage"`
	Timings           timings      `json:"timings"`
}

type chatChoice struct {
	Index        uint64          `json:"index"`
	Message      chatMessage     `json:"message"`
	FinishReason string          `json:"finish_reason"`
	Logprobs     json.RawMessage `json:"logprobs,omitempty"`
}

type usage struct {
	CompletionTokens    uint64             `json:"completion_tokens"`
	PromptTokens        uint64             `json:"prompt_tokens"`
	TotalTokens         uint64             `json:"total_tokens"`
	PromptTokensDetails promptTokenDetails `json:"prompt_tokens_details"`
}

type promptTokenDetails struct {
	CachedTokens uint64 `json:"cached_tokens"`
}

type timings struct {
	CacheTokens             uint64  `json:"cache_n"`
	PromptTokens            uint64  `json:"prompt_n"`
	PromptMilliseconds      float64 `json:"prompt_ms"`
	PromptPerTokenMillis    float64 `json:"prompt_per_token_ms"`
	PromptPerSecond         float64 `json:"prompt_per_second"`
	PredictedTokens         uint64  `json:"predicted_n"`
	PredictedMilliseconds   float64 `json:"predicted_ms"`
	PredictedPerTokenMillis float64 `json:"predicted_per_token_ms"`
	PredictedPerSecond      float64 `json:"predicted_per_second"`
}

type streamChunk struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	SystemFingerprint string         `json:"system_fingerprint"`
	Choices           []streamChoice `json:"choices"`
	Usage             *usage         `json:"usage,omitempty"`
	Timings           *timings       `json:"timings,omitempty"`
}

type streamChoice struct {
	Index        uint64      `json:"index"`
	Delta        streamDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type streamDelta struct {
	Role             string           `json:"role,omitempty"`
	Content          *string          `json:"content,omitempty"`
	ReasoningContent *string          `json:"reasoning_content,omitempty"`
	ToolCalls        []nativeToolCall `json:"tool_calls,omitempty"`
}
