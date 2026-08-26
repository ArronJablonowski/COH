package vllm

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type toolAccumulator struct {
	id        string
	typeName  string
	name      strings.Builder
	arguments strings.Builder
}

type streamReducer struct {
	adapter          *Adapter
	ctx              context.Context
	validatedRequest providercontract.ValidatedRequest
	request          providercontract.InferenceRequest
	tools            map[string]providercontract.Tool
	emit             StreamEmitter
	cohNext          uint64
	vendorID         string
	created          int64
	text             strings.Builder
	reasoning        strings.Builder
	toolCalls        map[uint64]*toolAccumulator
	finishReason     string
	trace            bytes.Buffer
	pending          providercontract.ValidatedResponse
	usageSeen        bool
	terminal         bool
	started          time.Time
}

func newStreamReducer(adapter *Adapter, ctx context.Context, validated providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, emit StreamEmitter) *streamReducer {
	return &streamReducer{adapter: adapter, ctx: ctx, validatedRequest: validated, request: request, tools: tools,
		emit: emit, toolCalls: make(map[uint64]*toolAccumulator), started: adapter.config.Clock().UTC()}
}

func (reducer *streamReducer) consume(canonical []byte, chunk streamChunk) error {
	if reducer.terminal || reducer.usageSeen {
		return newError(providercontract.Conflict, "stream_after_terminal", false)
	}
	if err := reducer.bindChunk(chunk); err != nil {
		return err
	}
	if reducer.trace.Len()+len(canonical)+1 > maximumResponseBytes {
		return newError(providercontract.Denied, "stream_too_large", false)
	}
	reducer.trace.Write(canonical)
	reducer.trace.WriteByte('\n')
	if len(chunk.Choices) == 0 {
		return reducer.consumeUsage(chunk)
	}
	if chunk.Usage != nil || len(chunk.Choices) != 1 || !nullJSON(chunk.PromptTokenIDs) || !nullJSON(chunk.PromptText) || !nullJSON(chunk.Metrics) {
		return newError(providercontract.Conflict, "stream_partial_metrics", false)
	}
	choice := chunk.Choices[0]
	if choice.Index != 0 {
		return newError(providercontract.Conflict, "stream_choice_index", false)
	}
	if choice.FinishReason != nil {
		return reducer.consumeFinish(choice)
	}
	if reducer.finishReason != "" {
		return newError(providercontract.Conflict, "stream_delta_after_finish", false)
	}
	return reducer.consumeDelta(choice.Delta)
}

func (reducer *streamReducer) bindChunk(chunk streamChunk) error {
	if !validText(chunk.ID, 128) || !strings.HasPrefix(chunk.ID, "chatcmpl-") ||
		chunk.Object != "chat.completion.chunk" || chunk.Created <= 0 || chunk.Model != reducer.request.Provider.ActualModel ||
		chunk.SystemFingerprint != nil && *chunk.SystemFingerprint != reducer.request.Provider.RuntimeDigest {
		return newError(providercontract.Denied, "stream_chunk_binding", false)
	}
	if reducer.vendorID == "" {
		reducer.vendorID, reducer.created = chunk.ID, chunk.Created
	} else if chunk.ID != reducer.vendorID || chunk.Created != reducer.created {
		return newError(providercontract.Denied, "stream_correlation_drift", false)
	}
	return nil
}

func (reducer *streamReducer) consumeDelta(delta streamDelta) error {
	if delta.Role != "" {
		if delta.Role != "assistant" || reducer.text.Len() != 0 || reducer.reasoning.Len() != 0 || len(reducer.toolCalls) != 0 ||
			delta.Content != nil && *delta.Content != "" || delta.Reasoning != nil || len(delta.ToolCalls) != 0 || !nullJSON(delta.Refusal) {
			return newError(providercontract.Denied, "stream_role_delta", false)
		}
		return nil
	}
	populated := 0
	if delta.Content != nil {
		if *delta.Content == "" || reducer.text.Len()+len(*delta.Content) > maximumResponseBytes {
			return newError(providercontract.InvalidInput, "stream_text_delta", false)
		}
		reducer.text.WriteString(*delta.Content)
		populated++
		if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "text_delta", TextDelta: *delta.Content}); err != nil {
			return err
		}
	}
	if delta.Reasoning != nil {
		if *delta.Reasoning == "" || reducer.reasoning.Len()+len(*delta.Reasoning) > maximumResponseBytes {
			return newError(providercontract.InvalidInput, "stream_reasoning_delta", false)
		}
		reducer.reasoning.WriteString(*delta.Reasoning)
		populated++
	}
	if len(delta.ToolCalls) > 0 {
		populated++
		for _, fragment := range delta.ToolCalls {
			if err := reducer.consumeToolFragment(fragment); err != nil {
				return err
			}
		}
	}
	if populated != 1 {
		return newError(providercontract.InvalidInput, "stream_delta_shape", false)
	}
	return nil
}

func (reducer *streamReducer) consumeToolFragment(fragment nativeToolCall) error {
	if fragment.Index == nil {
		return newError(providercontract.InvalidInput, "stream_tool_index_missing", false)
	}
	index := *fragment.Index
	if index >= uint64(reducer.adapter.config.Capability.Value().Limits.MaximumParallelToolCalls) {
		return newError(providercontract.Denied, "parallel_tool_limit", false)
	}
	accumulator, exists := reducer.toolCalls[index]
	if !exists {
		if index != uint64(len(reducer.toolCalls)) || !validText(fragment.ID, 128) || fragment.Type != "function" ||
			!validText(fragment.Function.Name, 128) {
			return newError(providercontract.Conflict, "stream_tool_start", false)
		}
		accumulator = &toolAccumulator{id: fragment.ID, typeName: fragment.Type}
		reducer.toolCalls[index] = accumulator
	} else if fragment.ID != "" || fragment.Type != "" {
		return newError(providercontract.Conflict, "stream_tool_identity_repeat", false)
	}
	if fragment.Function.Name != "" {
		if accumulator.name.Len()+len(fragment.Function.Name) > 128 {
			return newError(providercontract.Denied, "stream_tool_name_size", false)
		}
		accumulator.name.WriteString(fragment.Function.Name)
	}
	if fragment.Function.Arguments != "" {
		if accumulator.arguments.Len()+len(fragment.Function.Arguments) > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_tool_arguments_size", false)
		}
		accumulator.arguments.WriteString(fragment.Function.Arguments)
	}
	if fragment.Function.Name == "" && fragment.Function.Arguments == "" {
		return newError(providercontract.InvalidInput, "stream_tool_fragment_empty", false)
	}
	return nil
}

func (reducer *streamReducer) consumeFinish(choice streamChoice) error {
	if reducer.finishReason != "" || choice.Delta.Role != "" || choice.Delta.Content != nil ||
		choice.Delta.Reasoning != nil || len(choice.Delta.ToolCalls) != 0 || !nullJSON(choice.Logprobs) || !nullJSON(choice.StopReason) || !nullJSON(choice.TokenIDs) {
		return newError(providercontract.Conflict, "stream_finish_shape", false)
	}
	reason := *choice.FinishReason
	if reason != "stop" && reason != "length" && reason != "tool_calls" {
		return newError(providercontract.Unsupported, "vendor_finish_reason", false)
	}
	reducer.finishReason = reason
	return nil
}

func (reducer *streamReducer) consumeUsage(chunk streamChunk) error {
	if reducer.finishReason == "" || chunk.Usage == nil || chunk.SystemFingerprint == nil || *chunk.SystemFingerprint != reducer.request.Provider.RuntimeDigest ||
		!nullJSON(chunk.PromptTokenIDs) || !nullJSON(chunk.PromptText) || !nullJSON(chunk.Metrics) {
		return newError(providercontract.Conflict, "stream_usage_order", false)
	}
	message, err := reducer.completeMessage()
	if err != nil {
		return err
	}
	vendor := chatResponse{ID: chunk.ID, Object: "chat.completion", Created: chunk.Created, Model: chunk.Model,
		SystemFingerprint: chunk.SystemFingerprint, Choices: []chatChoice{{Index: 0, Message: message,
			FinishReason: &reducer.finishReason}}, Usage: *chunk.Usage}
	trace := bytes.TrimSuffix(reducer.trace.Bytes(), []byte{'\n'})
	reducer.pending, err = reducer.adapter.translateResponse(reducer.ctx, reducer.validatedRequest,
		reducer.request, reducer.tools, vendor, trace, reducer.started, reducer.adapter.config.Clock().UTC())
	if err != nil {
		return err
	}
	reducer.usageSeen = true
	return nil
}

func (reducer *streamReducer) completeMessage() (responseMessage, error) {
	indices := make([]int, 0, len(reducer.toolCalls))
	for index := range reducer.toolCalls {
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	calls := make([]nativeToolCall, 0, len(indices))
	for ordinal, index := range indices {
		if ordinal != index {
			return responseMessage{}, newError(providercontract.Conflict, "stream_tool_index", false)
		}
		item := reducer.toolCalls[uint64(index)]
		if item.name.Len() == 0 || item.arguments.Len() == 0 {
			return responseMessage{}, newError(providercontract.InvalidInput, "stream_tool_incomplete", false)
		}
		value := uint64(index)
		calls = append(calls, nativeToolCall{Index: &value, ID: item.id, Type: item.typeName,
			Function: nativeFunction{Name: item.name.String(), Arguments: item.arguments.String()}})
	}
	var content, reasoning *string
	if reducer.text.Len() > 0 {
		value := reducer.text.String()
		content = &value
	}
	if reducer.reasoning.Len() > 0 {
		value := reducer.reasoning.String()
		reasoning = &value
	}
	message := responseMessage{Role: "assistant", Content: content, Reasoning: reasoning, ToolCalls: calls}
	if message.Content == nil && message.Reasoning == nil && len(message.ToolCalls) == 0 {
		return responseMessage{}, newError(providercontract.InvalidInput, "vendor_response_empty", false)
	}
	return message, nil
}

func (reducer *streamReducer) finishDone() error {
	if reducer.terminal || !reducer.usageSeen || reducer.pending.Digest() == "" {
		return newError(providercontract.Conflict, "stream_done_order", false)
	}
	for _, item := range reducer.pending.Value().Items {
		copy := item
		if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "item", Item: &copy}); err != nil {
			return err
		}
	}
	value := reducer.pending.Value()
	if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "completed", Response: &value}); err != nil {
		return err
	}
	reducer.terminal = true
	return nil
}

func (reducer *streamReducer) finishAdapterError(err error) error {
	message := "model response stream failed"
	if Code(err) == providercontract.Canceled {
		message = "model response stream was canceled"
	} else if Code(err) == providercontract.Timeout {
		message = "model response stream timed out"
	}
	terminal := providercontract.TerminalError{Code: string(Code(err)), Reason: Reason(err), Message: message, Retryable: Retryable(err)}
	if emitErr := reducer.emitCOH(providercontract.StreamEvent{Kind: "error", Error: &terminal}); emitErr != nil {
		return emitErr
	}
	reducer.terminal = true
	return nil
}

func (reducer *streamReducer) emitCOH(event providercontract.StreamEvent) error {
	event.SchemaVersion, event.ContractVersion = providercontract.StreamEventSchemaVersion, providercontract.ContractVersion
	event.RequestID, event.AttemptID, event.Sequence = reducer.request.RequestID, reducer.request.AttemptID, reducer.cohNext
	event.ObservedAt = formatTimestamp(reducer.adapter.config.Clock())
	encoded, _ := json.Marshal(event)
	decodeContext := reducer.ctx
	if event.Kind == "error" {
		decodeContext = context.WithoutCancel(reducer.ctx)
	}
	validated, err := providercontract.DecodeStreamEvent(decodeContext, encoded)
	if err != nil {
		return newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	if err := reducer.emit(validated); err != nil {
		return newError(providercontract.Unavailable, "stream_emitter_failed", false)
	}
	reducer.cohNext++
	return nil
}
