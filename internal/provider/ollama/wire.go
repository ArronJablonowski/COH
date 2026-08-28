package ollama

import "encoding/json"

type versionResponse struct {
	Version string `json:"version"`
}

type tagsResponse struct {
	Models []modelRecord `json:"models"`
}

type modelRecord struct {
	Name         string       `json:"name"`
	Model        string       `json:"model"`
	ModifiedAt   string       `json:"modified_at"`
	Size         uint64       `json:"size"`
	Digest       string       `json:"digest"`
	Details      modelDetails `json:"details"`
	Capabilities []string     `json:"capabilities,omitempty"`
}

type modelDetails struct {
	ParentModel       string   `json:"parent_model,omitempty"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
	ContextLength     uint64   `json:"context_length,omitempty"`
	EmbeddingLength   uint64   `json:"embedding_length,omitempty"`
}

type showRequest struct {
	Model   string `json:"model"`
	Verbose bool   `json:"verbose"`
}

type showResponse struct {
	Parameters    string                     `json:"parameters"`
	License       json.RawMessage            `json:"license"`
	System        string                     `json:"system,omitempty"`
	ModifiedAt    string                     `json:"modified_at"`
	Details       modelDetails               `json:"details"`
	Template      string                     `json:"template"`
	Capabilities  []string                   `json:"capabilities"`
	ModelInfo     map[string]json.RawMessage `json:"model_info"`
	Modelfile     string                     `json:"modelfile,omitempty"`
	ProjectorInfo map[string]json.RawMessage `json:"projector_info,omitempty"`
	Requires      string                     `json:"requires,omitempty"`
	Tensors       []tensorRecord             `json:"tensors,omitempty"`
}

type tensorRecord struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Shape []uint64 `json:"shape"`
}

type chatRequest struct {
	Model     string          `json:"model"`
	Messages  []chatMessage   `json:"messages"`
	Tools     []functionTool  `json:"tools,omitempty"`
	Format    json.RawMessage `json:"format,omitempty"`
	Options   chatOptions     `json:"options"`
	Stream    bool            `json:"stream"`
	Think     bool            `json:"think"`
	KeepAlive int             `json:"keep_alive"`
}

type chatOptions struct {
	ContextLength  uint64  `json:"num_ctx"`
	MaximumPredict uint64  `json:"num_predict"`
	Temperature    float64 `json:"temperature"`
	TopP           float64 `json:"top_p"`
	Seed           uint32  `json:"seed"`
}

type chatMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	Thinking  string           `json:"thinking,omitempty"`
	ToolCalls []nativeToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
	Images    []string         `json:"images,omitempty"`
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
	ID       string             `json:"id,omitempty"`
	Type     string             `json:"type,omitempty"`
	Function nativeFunctionCall `json:"function"`
}

type nativeFunctionCall struct {
	Index     *uint64         `json:"index,omitempty"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type chatResponse struct {
	Model              string            `json:"model"`
	CreatedAt          string            `json:"created_at"`
	Message            chatMessage       `json:"message"`
	Done               bool              `json:"done"`
	DoneReason         string            `json:"done_reason"`
	TotalDuration      uint64            `json:"total_duration"`
	LoadDuration       uint64            `json:"load_duration"`
	PromptEvalCount    uint64            `json:"prompt_eval_count"`
	PromptEvalDuration uint64            `json:"prompt_eval_duration"`
	EvalCount          uint64            `json:"eval_count"`
	EvalDuration       uint64            `json:"eval_duration"`
	Logprobs           []json.RawMessage `json:"logprobs,omitempty"`
}
