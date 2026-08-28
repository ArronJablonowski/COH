package codexruntime

import "encoding/json"

type rpcRequest struct {
	Method string `json:"method"`
	ID     uint64 `json:"id"`
	Params any    `json:"params"`
}
type rpcNotification struct {
	Method string `json:"method"`
	Params any    `json:"params"`
}
type rpcError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}
type inboundEnvelope struct {
	Method string          `json:"method,omitempty"`
	ID     json.RawMessage `json:"id,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

type initializeParams struct {
	ClientInfo   clientInfo         `json:"clientInfo"`
	Capabilities clientCapabilities `json:"capabilities"`
}
type clientInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"`
}
type clientCapabilities struct {
	ExperimentalAPI bool `json:"experimentalApi"`
}
type initializeResult struct {
	CodexHome      string `json:"codexHome"`
	UserAgent      string `json:"userAgent"`
	PlatformFamily string `json:"platformFamily"`
	PlatformOS     string `json:"platformOs"`
}

type threadStartParams struct {
	Model          string        `json:"model"`
	CWD            string        `json:"cwd"`
	ApprovalPolicy string        `json:"approvalPolicy"`
	Sandbox        string        `json:"sandbox"`
	Ephemeral      bool          `json:"ephemeral"`
	DynamicTools   []dynamicTool `json:"dynamicTools"`
}
type dynamicTool struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	DeferLoading bool            `json:"deferLoading"`
}
type threadStartResult struct {
	Thread             threadRecord `json:"thread"`
	InstructionSources []string     `json:"instructionSources"`
}
type threadStartedParams struct {
	Thread threadRecord `json:"thread"`
}
type threadRecord struct {
	ID                   string            `json:"id"`
	SessionID            string            `json:"sessionId"`
	Preview              string            `json:"preview"`
	Ephemeral            bool              `json:"ephemeral"`
	ModelProvider        string            `json:"modelProvider"`
	CreatedAt            int64             `json:"createdAt"`
	UpdatedAt            int64             `json:"updatedAt"`
	CWD                  string            `json:"cwd"`
	CLIVersion           string            `json:"cliVersion"`
	Source               json.RawMessage   `json:"source"`
	Status               json.RawMessage   `json:"status"`
	Turns                []json.RawMessage `json:"turns"`
	AgentNickname        json.RawMessage   `json:"agentNickname,omitempty"`
	AgentRole            json.RawMessage   `json:"agentRole,omitempty"`
	CanAcceptDirectInput json.RawMessage   `json:"canAcceptDirectInput,omitempty"`
	Extra                json.RawMessage   `json:"extra,omitempty"`
	ForkedFromID         json.RawMessage   `json:"forkedFromId,omitempty"`
	GitInfo              json.RawMessage   `json:"gitInfo,omitempty"`
	HistoryMode          string            `json:"historyMode,omitempty"`
	Name                 json.RawMessage   `json:"name,omitempty"`
	ParentThreadID       json.RawMessage   `json:"parentThreadId,omitempty"`
	Path                 json.RawMessage   `json:"path,omitempty"`
	RecencyAt            json.RawMessage   `json:"recencyAt,omitempty"`
	ThreadSource         json.RawMessage   `json:"threadSource,omitempty"`
}

type turnStartParams struct {
	ThreadID       string          `json:"threadId"`
	Input          []userInput     `json:"input"`
	CWD            string          `json:"cwd"`
	ApprovalPolicy string          `json:"approvalPolicy"`
	SandboxPolicy  sandboxPolicy   `json:"sandboxPolicy"`
	Model          string          `json:"model"`
	Effort         string          `json:"effort"`
	Summary        string          `json:"summary"`
	OutputSchema   json.RawMessage `json:"outputSchema,omitempty"`
}
type userInput struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type sandboxPolicy struct {
	Type   string     `json:"type"`
	Access readAccess `json:"access"`
}
type readAccess struct {
	Type                    string   `json:"type"`
	IncludePlatformDefaults bool     `json:"includePlatformDefaults"`
	ReadableRoots           []string `json:"readableRoots"`
}
type turnStartResult struct {
	Turn turnRecord `json:"turn"`
}
type turnStartedParams struct {
	ThreadID string     `json:"threadId"`
	Turn     turnRecord `json:"turn"`
}
type turnRecord struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Items       []json.RawMessage `json:"items"`
	Error       json.RawMessage   `json:"error"`
	CompletedAt json.RawMessage   `json:"completedAt,omitempty"`
	DurationMS  json.RawMessage   `json:"durationMs,omitempty"`
	ItemsView   string            `json:"itemsView,omitempty"`
	StartedAt   json.RawMessage   `json:"startedAt,omitempty"`
}
type turnInterruptParams struct {
	ThreadID string `json:"threadId"`
	TurnID   string `json:"turnId"`
}

type agentDeltaParams struct {
	ThreadID string `json:"threadId"`
	TurnID   string `json:"turnId"`
	ItemID   string `json:"itemId"`
	Delta    string `json:"delta"`
}
type itemEventParams struct {
	ThreadID string     `json:"threadId"`
	TurnID   string     `json:"turnId"`
	Item     itemRecord `json:"item"`
}
type itemRecord struct {
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	Status         string          `json:"status"`
	Text           string          `json:"text,omitempty"`
	MemoryCitation json.RawMessage `json:"memoryCitation,omitempty"`
	Phase          json.RawMessage `json:"phase,omitempty"`
	Content        []string        `json:"content,omitempty"`
	Summary        []string        `json:"summary,omitempty"`
	Tool           string          `json:"tool,omitempty"`
	Namespace      *string         `json:"namespace,omitempty"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
	ContentItems   json.RawMessage `json:"contentItems,omitempty"`
	Success        *bool           `json:"success,omitempty"`
	DurationMS     *uint64         `json:"durationMs,omitempty"`
}
type dynamicToolCallParams struct {
	ThreadID  string          `json:"threadId"`
	TurnID    string          `json:"turnId"`
	CallID    string          `json:"callId"`
	Tool      string          `json:"tool"`
	Namespace *string         `json:"namespace"`
	Arguments json.RawMessage `json:"arguments"`
}
type dynamicToolCallResponse struct {
	ContentItems []dynamicToolContent `json:"contentItems"`
	Success      bool                 `json:"success"`
}
type dynamicToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type approvalResponse struct {
	Decision string `json:"decision"`
}

type turnCompletedParams struct {
	ThreadID string     `json:"threadId"`
	Turn     turnRecord `json:"turn"`
}
type reroutedParams struct {
	ThreadID  string `json:"threadId"`
	TurnID    string `json:"turnId"`
	FromModel string `json:"fromModel"`
	ToModel   string `json:"toModel"`
	Reason    string `json:"reason"`
}
type tokenUsageParams struct {
	ThreadID   string           `json:"threadId"`
	TurnID     string           `json:"turnId"`
	TokenUsage threadTokenUsage `json:"tokenUsage"`
}
type threadTokenUsage struct {
	Last               tokenUsage `json:"last"`
	Total              tokenUsage `json:"total"`
	ModelContextWindow *uint64    `json:"modelContextWindow"`
}
type tokenUsage struct {
	InputTokens           uint64 `json:"inputTokens"`
	CachedInputTokens     uint64 `json:"cachedInputTokens"`
	CacheWriteInputTokens uint64 `json:"cacheWriteInputTokens"`
	OutputTokens          uint64 `json:"outputTokens"`
	ReasoningOutputTokens uint64 `json:"reasoningOutputTokens"`
	TotalTokens           uint64 `json:"totalTokens"`
}

type execEvent struct {
	Type     string          `json:"type"`
	ThreadID string          `json:"thread_id,omitempty"`
	Item     *execItem       `json:"item,omitempty"`
	Usage    *execUsage      `json:"usage,omitempty"`
	Error    json.RawMessage `json:"error,omitempty"`
}
type execItem struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Text    string `json:"text,omitempty"`
	Status  string `json:"status,omitempty"`
	Command string `json:"command,omitempty"`
}
type execUsage struct {
	InputTokens           uint64 `json:"input_tokens"`
	CachedInputTokens     uint64 `json:"cached_input_tokens"`
	CacheWriteInputTokens uint64 `json:"cache_write_input_tokens"`
	OutputTokens          uint64 `json:"output_tokens"`
	ReasoningOutputTokens uint64 `json:"reasoning_output_tokens"`
}
