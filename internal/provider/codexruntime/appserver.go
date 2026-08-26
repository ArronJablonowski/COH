package codexruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	traceDomain     = "COH-CODEX-RUNTIME-TRACE-V1\x00"
	reasoningDomain = "COH-CODEX-RUNTIME-REASONING-V1\x00"
)

type runState struct {
	adapter                  *Adapter
	ctx                      context.Context
	validated                providercontract.ValidatedRequest
	request                  providercontract.InferenceRequest
	translation              translation
	transport                RPCTransport
	threadID, turnID, itemID string
	trace                    bytes.Buffer
	events                   uint32
	text, reasoning          strings.Builder
	items                    []providercontract.ContentItem
	toolCalls                map[string]*toolLifecycle
	usage                    providercontract.Usage
	usageSeen, terminal      bool
	traceOverflow            bool
	expectedCodexHome        string
	started                  time.Time
}

type toolLifecycle struct {
	name, arguments string
	answered        bool
	completed       bool
	success         bool
}

func (a *Adapter) Invoke(ctx context.Context, request providercontract.ValidatedRequest) (providercontract.ValidatedResponse, error) {
	v, timeout, err := a.validateDispatch(ctx, request)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	translated, err := a.translateRequest(ctx, v)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if v.Provider.RuntimeName == "codex-exec" {
		return a.invokeBatch(runCtx, request, v, translated)
	}
	return a.invokeAppServer(runCtx, request, v, translated, nil)
}

type deltaEmitter func(string) error

func (a *Adapter) invokeAppServer(ctx context.Context, validated providercontract.ValidatedRequest, request providercontract.InferenceRequest, translated translation, emit deltaEmitter) (providercontract.ValidatedResponse, error) {
	transport, observation, err := a.config.Factory.Open(ctx)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Unavailable, "app_server_launch_failed", true)
	}
	if transport == nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Unavailable, "app_server_transport_missing", true)
	}
	defer transport.Close()
	if err := a.verifyObservation(request, observation, "stdio"); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	state := &runState{adapter: a, ctx: ctx, validated: validated, request: request, translation: translated, transport: transport, toolCalls: make(map[string]*toolLifecycle), expectedCodexHome: observation.CodexHome, started: a.config.Clock().UTC()}
	if state.started.IsZero() {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "clock_unavailable", false)
	}
	if err := state.handshake(); err != nil {
		return providercontract.ValidatedResponse{}, state.withProvenance(err)
	}
	response, err := state.consume(emit)
	if err != nil {
		return providercontract.ValidatedResponse{}, state.withProvenance(err)
	}
	return response, nil
}

func (s *runState) handshake() error {
	init := rpcRequest{Method: "initialize", ID: 1, Params: initializeParams{ClientInfo: clientInfo{Name: "coh", Title: "Cyber Operations Harness", Version: AdapterVersion}, Capabilities: clientCapabilities{ExperimentalAPI: true}}}
	if err := s.send(init); err != nil {
		return err
	}
	var initialized initializeResult
	docs, err := receiveResponseWithNotifications(s.ctx, s.transport, 1, &initialized, nil)
	if err != nil {
		return err
	}
	s.addDocs(docs)
	if initialized.CodexHome != s.expectedCodexHome || !validText(initialized.UserAgent, 256) || !validText(initialized.PlatformFamily, 64) || !validText(initialized.PlatformOS, 64) {
		return newError(providercontract.Denied, "initialize_identity_invalid", false)
	}
	if err := s.send(rpcNotification{Method: "initialized", Params: struct{}{}}); err != nil {
		return err
	}
	start := threadStartParams{Model: s.request.Provider.RequestedModel, CWD: s.adapter.config.Workspace, ApprovalPolicy: "untrusted", Sandbox: "read-only", Ephemeral: true, DynamicTools: s.translation.Tools}
	if err := s.send(rpcRequest{Method: "thread/start", ID: 2, Params: start}); err != nil {
		return err
	}
	var thread threadStartResult
	docs, err = receiveResponseWithNotifications(s.ctx, s.transport, 2, &thread, nil)
	if err != nil {
		return err
	}
	s.addDocs(docs)
	if !validText(thread.Thread.ID, 128) || thread.Thread.SessionID != thread.Thread.ID || !thread.Thread.Ephemeral || thread.Thread.ModelProvider != "openai" || thread.Thread.CWD != s.adapter.config.Workspace || thread.Thread.CLIVersion != RuntimeVersion || thread.Thread.CreatedAt <= 0 || thread.Thread.UpdatedAt <= 0 || len(thread.Thread.Turns) != 0 || !rawStringEqual(thread.Thread.Source, "appServer") || !threadStatusEqual(thread.Thread.Status, "idle") || len(thread.InstructionSources) != 0 {
		return newError(providercontract.Denied, "thread_identity_invalid", false)
	}
	s.threadID = thread.Thread.ID
	turn := turnStartParams{ThreadID: s.threadID, Input: []userInput{{Type: "text", Text: s.translation.Prompt}}, CWD: s.adapter.config.Workspace, ApprovalPolicy: "untrusted", SandboxPolicy: sandboxPolicy{Type: "readOnly", Access: readAccess{Type: "restricted", IncludePlatformDefaults: false, ReadableRoots: []string{s.adapter.config.Workspace}}}, Model: s.request.Provider.RequestedModel, Effort: "medium", Summary: "concise", OutputSchema: s.translation.OutputSchema}
	if err := s.send(rpcRequest{Method: "turn/start", ID: 3, Params: turn}); err != nil {
		return err
	}
	var started turnStartResult
	notify := func(envelope inboundEnvelope, _ []byte) error {
		if envelope.Method != "thread/started" {
			return newError(providercontract.Conflict, "unexpected_pre_turn_notification", false)
		}
		var value threadStartedParams
		if err := decodeParams(envelope.Params, &value); err != nil {
			return err
		}
		if value.Thread.ID != s.threadID {
			return newError(providercontract.Conflict, "thread_correlation", false)
		}
		return nil
	}
	docs, err = receiveResponseWithNotifications(s.ctx, s.transport, 3, &started, notify)
	if err != nil {
		return err
	}
	s.addDocs(docs)
	if !validText(started.Turn.ID, 128) || started.Turn.Status != "inProgress" || len(started.Turn.Items) != 0 || !nullJSON(started.Turn.Error) {
		return newError(providercontract.Denied, "turn_identity_invalid", false)
	}
	s.turnID = started.Turn.ID
	if s.traceOverflow {
		return newError(providercontract.Denied, "trace_limit", false)
	}
	return nil
}

func (s *runState) consume(emit deltaEmitter) (providercontract.ValidatedResponse, error) {
	for !s.terminal {
		if s.events >= maximumEvents {
			return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "event_limit", false)
		}
		envelope, canonical, err := receiveDocument(s.ctx, s.transport)
		if err != nil {
			if (Code(err) == providercontract.Canceled || Code(err) == providercontract.Timeout) && s.threadID != "" && s.turnID != "" {
				interruptCtx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), time.Second)
				document, _ := sendDocument(interruptCtx, s.transport, rpcRequest{Method: "turn/interrupt", ID: 4, Params: turnInterruptParams{ThreadID: s.threadID, TurnID: s.turnID}})
				cancel()
				if len(document) > 0 {
					s.addTrace('C', document)
				}
			}
			return providercontract.ValidatedResponse{}, err
		}
		s.addTrace('S', canonical)
		if s.traceOverflow {
			return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "trace_limit", false)
		}
		s.events++
		if envelope.Method == "" {
			return providercontract.ValidatedResponse{}, newError(providercontract.Conflict, "unsolicited_rpc_response", false)
		}
		if len(envelope.ID) > 0 {
			if err := s.handleServerRequest(envelope); err != nil {
				return providercontract.ValidatedResponse{}, err
			}
			continue
		}
		if err := s.handleNotification(envelope, emit); err != nil {
			return providercontract.ValidatedResponse{}, err
		}
	}
	return s.buildResponse()
}

func (s *runState) handleServerRequest(envelope inboundEnvelope) error {
	if !validRPCID(envelope.ID) {
		return newError(providercontract.InvalidInput, "server_request_id", false)
	}
	if envelope.Method != "item/tool/call" {
		_, _ = sendDocument(context.WithoutCancel(s.ctx), s.transport, rpcServerResponse{ID: envelope.ID, Result: approvalResponse{Decision: "cancel"}})
		return newError(providercontract.Denied, "native_tool_not_authorized", false)
	}
	var call dynamicToolCallParams
	if err := decodeParams(envelope.Params, &call); err != nil {
		return err
	}
	if call.ThreadID != s.threadID || call.TurnID != s.turnID || call.Namespace != nil || !validText(call.CallID, 128) {
		return newError(providercontract.Conflict, "tool_call_correlation", false)
	}
	tool, ok := s.translation.ToolMap[call.Tool]
	canonical, err := canonicalJSON(call.Arguments)
	if !ok || err != nil || !jsonObject(canonical) {
		return newError(providercontract.Denied, "tool_not_allowed", false)
	}
	lifecycle, started := s.toolCalls[call.CallID]
	if !started || lifecycle.name != call.Tool || lifecycle.arguments != string(canonical) || lifecycle.answered || lifecycle.completed {
		return newError(providercontract.Conflict, "tool_call_lifecycle", false)
	}
	result, err := s.adapter.config.Tools.Call(s.ctx, ToolCall{RequestID: s.request.RequestID, AttemptID: s.request.AttemptID, CallID: call.CallID, Name: tool.Name, InputSchemaDigest: tool.InputSchemaDigest, OutputSchemaDigest: tool.OutputSchemaDigest, Arguments: canonical})
	if err != nil {
		return newError(providercontract.Unavailable, "tool_broker_failed", true)
	}
	value, err := canonicalJSON(result.Value)
	if err != nil || !jsonObject(value) {
		return newError(providercontract.InvalidInput, "tool_result_invalid", false)
	}
	digestValue, digestErr := providercontract.DigestToolResult(value)
	if digestErr != nil || digestValue != result.ResultDigest {
		return newError(providercontract.Denied, "tool_result_digest", false)
	}
	if result.Outcome != "succeeded" && result.Outcome != "denied" && result.Outcome != "canceled" && result.Outcome != "timeout" && result.Outcome != "failed" && result.Outcome != "uncertain" {
		return newError(providercontract.InvalidInput, "tool_result_outcome", false)
	}
	payload, _ := json.Marshal(map[string]any{"outcome": result.Outcome, "value": json.RawMessage(value), "result_digest": result.ResultDigest})
	response := rpcServerResponse{ID: envelope.ID, Result: dynamicToolCallResponse{ContentItems: []dynamicToolContent{{Type: "inputText", Text: string(payload)}}, Success: result.Outcome == "succeeded"}}
	document, err := sendDocument(s.ctx, s.transport, response)
	if err != nil {
		return err
	}
	s.addTrace('C', document)
	if s.traceOverflow {
		return newError(providercontract.Denied, "trace_limit", false)
	}
	s.items = append(s.items, providercontract.ContentItem{Kind: "tool_call", CallID: call.CallID, ToolName: tool.Name, Arguments: canonical, InputSchemaDigest: tool.InputSchemaDigest})
	s.items = append(s.items, providercontract.ContentItem{Kind: "tool_result", CallID: call.CallID, Outcome: result.Outcome, Value: value, OutputSchemaDigest: tool.OutputSchemaDigest, ResultDigest: result.ResultDigest})
	lifecycle.answered = true
	lifecycle.success = result.Outcome == "succeeded"
	return nil
}

func (s *runState) handleNotification(envelope inboundEnvelope, emit deltaEmitter) error {
	switch envelope.Method {
	case "thread/started":
		var p threadStartedParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if p.Thread.ID != s.threadID {
			return newError(providercontract.Conflict, "thread_correlation", false)
		}
	case "turn/started":
		var p turnStartedParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if p.ThreadID != s.threadID || p.Turn.ID != s.turnID || p.Turn.Status != "inProgress" {
			return newError(providercontract.Conflict, "turn_correlation", false)
		}
	case "item/agentMessage/delta":
		var p agentDeltaParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if err := s.correlate(p.ThreadID, p.TurnID); err != nil {
			return err
		}
		if !validText(p.ItemID, 128) || p.Delta == "" || s.text.Len()+len(p.Delta) > maximumTraceBytes {
			return newError(providercontract.InvalidInput, "agent_delta", false)
		}
		if s.itemID == "" {
			s.itemID = p.ItemID
		} else if s.itemID != p.ItemID {
			return newError(providercontract.Conflict, "agent_item_correlation", false)
		}
		s.text.WriteString(p.Delta)
		if emit != nil {
			return emit(p.Delta)
		}
	case "item/started", "item/completed":
		var p itemEventParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if err := s.correlate(p.ThreadID, p.TurnID); err != nil {
			return err
		}
		return s.handleItem(envelope.Method, p.Item)
	case "thread/tokenUsage/updated":
		var p tokenUsageParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if err := s.correlate(p.ThreadID, p.TurnID); err != nil {
			return err
		}
		u := p.TokenUsage.Total
		if u.TotalTokens != u.InputTokens+u.OutputTokens || u.CachedInputTokens > u.InputTokens || u.ReasoningOutputTokens > u.OutputTokens {
			return newError(providercontract.Denied, "usage_invalid", false)
		}
		s.usage = providercontract.Usage{InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, TotalTokens: u.TotalTokens, CachedInputTokens: u.CachedInputTokens, ReasoningTokens: u.ReasoningOutputTokens}
		s.usageSeen = true
	case "model/rerouted":
		var p reroutedParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		return newError(providercontract.Denied, "model_rerouted", false)
	case "turn/completed":
		var p turnCompletedParams
		if err := decodeParams(envelope.Params, &p); err != nil {
			return err
		}
		if p.ThreadID != s.threadID || p.Turn.ID != s.turnID {
			return newError(providercontract.Conflict, "turn_correlation", false)
		}
		if p.Turn.Status == "interrupted" {
			return newError(providercontract.Canceled, "turn_interrupted", false)
		}
		if p.Turn.Status != "completed" || !nullJSON(p.Turn.Error) {
			return newError(providercontract.Unavailable, "turn_failed", false)
		}
		if !s.usageSeen {
			return newError(providercontract.Conflict, "terminal_usage_missing", false)
		}
		for _, lifecycle := range s.toolCalls {
			if !lifecycle.answered || !lifecycle.completed {
				return newError(providercontract.Conflict, "tool_call_incomplete", false)
			}
		}
		s.terminal = true
	default:
		return newError(providercontract.Unsupported, "notification_not_supported", false)
	}
	return nil
}

func (s *runState) handleItem(method string, item itemRecord) error {
	if !validText(item.ID, 128) {
		return newError(providercontract.InvalidInput, "item_identity", false)
	}
	if method == "item/started" {
		if item.Type != "agentMessage" && item.Type != "reasoning" && item.Type != "dynamicToolCall" {
			return newError(providercontract.Denied, "native_item_not_authorized", false)
		}
		if item.Type == "dynamicToolCall" {
			if item.Status != "inProgress" || item.Namespace != nil {
				return newError(providercontract.Denied, "dynamic_tool_item_invalid", false)
			}
			if _, ok := s.translation.ToolMap[item.Tool]; !ok {
				return newError(providercontract.Denied, "dynamic_tool_item_invalid", false)
			}
			arguments, err := canonicalJSON(item.Arguments)
			if err != nil || !jsonObject(arguments) {
				return newError(providercontract.Denied, "dynamic_tool_item_invalid", false)
			}
			if _, exists := s.toolCalls[item.ID]; exists {
				return newError(providercontract.Conflict, "tool_call_duplicate", false)
			}
			s.toolCalls[item.ID] = &toolLifecycle{name: item.Tool, arguments: string(arguments)}
		}
		return nil
	}
	switch item.Type {
	case "agentMessage":
		if item.Text == "" {
			return newError(providercontract.InvalidInput, "agent_message_empty", false)
		}
		if s.itemID != "" && item.ID != s.itemID {
			return newError(providercontract.Conflict, "agent_item_correlation", false)
		}
		if s.text.Len() == 0 {
			s.text.WriteString(item.Text)
		} else if s.text.String() != item.Text {
			return newError(providercontract.Conflict, "agent_message_drift", false)
		}
	case "reasoning":
		for _, part := range append(item.Summary, item.Content...) {
			if !validText(part, 1<<20) || s.reasoning.Len()+len(part) > maximumTraceBytes {
				return newError(providercontract.InvalidInput, "reasoning_invalid", false)
			}
			s.reasoning.WriteString(part)
		}
	case "dynamicToolCall":
		lifecycle, ok := s.toolCalls[item.ID]
		arguments, err := canonicalJSON(item.Arguments)
		if !ok || err != nil || lifecycle.name != item.Tool || lifecycle.arguments != string(arguments) || !lifecycle.answered || lifecycle.completed || item.Status != "completed" || item.Namespace != nil || item.Success == nil || *item.Success != lifecycle.success {
			return newError(providercontract.Denied, "dynamic_tool_item_invalid", false)
		}
		lifecycle.completed = true
	default:
		return newError(providercontract.Denied, "native_item_not_authorized", false)
	}
	return nil
}

func (s *runState) correlate(thread, turn string) error {
	if thread != s.threadID || turn != s.turnID {
		return newError(providercontract.Conflict, "event_correlation", false)
	}
	return nil
}
func (s *runState) send(value any) error {
	document, err := sendDocument(s.ctx, s.transport, value)
	if err == nil {
		s.addTrace('C', document)
	}
	return err
}
func (s *runState) addDocs(values [][]byte) {
	for _, value := range values {
		s.addTrace('S', value)
	}
}
func (s *runState) addTrace(direction byte, value []byte) {
	if s.trace.Len()+len(value)+3 > maximumTraceBytes {
		s.traceOverflow = true
		return
	}
	s.trace.WriteByte(direction)
	s.trace.WriteByte(':')
	s.trace.Write(value)
	s.trace.WriteByte('\n')
}

func (s *runState) withProvenance(err error) error {
	if err == nil || s.trace.Len() == 0 {
		return err
	}
	var value *Error
	if !errors.As(err, &value) {
		return &Error{Code: Code(err), Reason: Reason(err), Retryable: Retryable(err), ProvenanceDigest: digest(traceDomain, append([]byte(s.validated.Digest()+"\x00"), s.trace.Bytes()...))}
	}
	copy := *value
	copy.ProvenanceDigest = digest(traceDomain, append([]byte(s.validated.Digest()+"\x00"), s.trace.Bytes()...))
	return &copy
}

func (s *runState) buildResponse() (providercontract.ValidatedResponse, error) {
	if s.traceOverflow {
		return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "trace_limit", false)
	}
	if !s.terminal || !s.usageSeen || s.text.Len() == 0 {
		return providercontract.ValidatedResponse{}, newError(providercontract.Conflict, "response_incomplete", false)
	}
	if err := s.adapter.validateUsage(s.request, s.usage); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if s.request.OutputConstraint.Kind == "json_schema" {
		canonical, err := canonicalJSON([]byte(s.text.String()))
		if err != nil || !jsonObject(canonical) {
			return providercontract.ValidatedResponse{}, newError(providercontract.InvalidInput, "structured_output_invalid", false)
		}
		s.items = append([]providercontract.ContentItem{{Kind: "output_json", Value: canonical, SchemaDigest: s.request.OutputConstraint.SchemaDigest}}, s.items...)
	} else {
		s.items = append([]providercontract.ContentItem{{Kind: "text", Text: s.text.String()}}, s.items...)
	}
	if s.reasoning.Len() > 0 {
		envelope, _ := json.Marshal(map[string]string{"reasoning": s.reasoning.String()})
		canonical, _ := canonicalJSON(envelope)
		itemDigest := digest(reasoningDomain, canonical)
		reference := deterministicUUID("COH-CODEX-RUNTIME-REASONING-ID-V1\x00", s.request.RequestID+"\x00"+itemDigest)
		if err := s.adapter.config.Reasoning.Put(s.ctx, reference, itemDigest, canonical); err != nil {
			return providercontract.ValidatedResponse{}, newError(providercontract.Unavailable, "reasoning_persistence_failed", true)
		}
		s.items = append(s.items, providercontract.ContentItem{Kind: "reasoning_ref", ReferenceID: reference, Digest: itemDigest})
	}
	completed := s.adapter.config.Clock().UTC()
	if completed.IsZero() || completed.Before(s.started) {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "clock_invalid", false)
	}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion, ContractVersion: providercontract.ContractVersion, ResponseID: deterministicUUID("COH-CODEX-RUNTIME-RESPONSE-ID-V1\x00", s.validated.Digest()+"\x00"+s.trace.String()), RequestID: s.request.RequestID, AttemptID: s.request.AttemptID, Provider: s.request.Provider, CapabilityDigest: s.request.CapabilityDigest, QualificationID: s.request.QualificationID, Outcome: "succeeded", Items: s.items, Usage: s.usage, State: providercontract.State{Mode: "stateless"}, StartedAt: formatTimestamp(s.started), CompletedAt: formatTimestamp(completed), ProvenanceDigest: digest(traceDomain, append([]byte(s.validated.Digest()+"\x00"), s.trace.Bytes()...))}
	encoded, err := json.Marshal(response)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "response_encoding", false)
	}
	validated, err := providercontract.DecodeResponse(s.ctx, encoded)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	return validated, nil
}

func nullJSON(value json.RawMessage) bool {
	return len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func rawStringEqual(value json.RawMessage, wanted string) bool {
	var text string
	return json.Unmarshal(value, &text) == nil && text == wanted
}

func threadStatusEqual(value json.RawMessage, wanted string) bool {
	var status struct {
		Type string `json:"type"`
	}
	return decodeExact(value, &status) == nil && status.Type == wanted
}
