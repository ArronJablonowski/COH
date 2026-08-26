package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type streamReducer struct {
	adapter          *Adapter
	ctx              context.Context
	validatedRequest providercontract.ValidatedRequest
	request          providercontract.InferenceRequest
	tools            map[string]providercontract.Tool
	emit             StreamEmitter
	cohNext          uint64
	lastCreated      time.Time
	text             bytes.Buffer
	thinking         bytes.Buffer
	toolCalls        map[uint64]nativeToolCall
	trace            bytes.Buffer
	terminal         bool
}

func newStreamReducer(adapter *Adapter, ctx context.Context, validated providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, emit StreamEmitter) *streamReducer {
	return &streamReducer{adapter: adapter, ctx: ctx, validatedRequest: validated, request: request, tools: tools,
		emit: emit, toolCalls: make(map[uint64]nativeToolCall)}
}

func (reducer *streamReducer) consume(canonical []byte, chunk chatResponse) error {
	if reducer.terminal {
		return newError(providercontract.Conflict, "stream_after_terminal", false)
	}
	created, err := time.Parse(time.RFC3339Nano, chunk.CreatedAt)
	if err != nil || !reducer.lastCreated.IsZero() && created.Before(reducer.lastCreated) ||
		chunk.Model != reducer.request.Provider.ActualModel || chunk.Message.Role != "assistant" ||
		len(chunk.Message.Images) != 0 || len(chunk.Logprobs) != 0 {
		return newError(providercontract.Denied, "stream_chunk_binding", false)
	}
	reducer.lastCreated = created
	if reducer.trace.Len()+len(canonical)+1 > maximumResponseBytes {
		return newError(providercontract.Denied, "stream_too_large", false)
	}
	reducer.trace.Write(canonical)
	reducer.trace.WriteByte('\n')
	if err := reducer.accumulateMessage(chunk.Message); err != nil {
		return err
	}
	if !chunk.Done {
		if chunk.DoneReason != "" || chunk.TotalDuration != 0 || chunk.LoadDuration != 0 || chunk.PromptEvalCount != 0 ||
			chunk.PromptEvalDuration != 0 || chunk.EvalCount != 0 || chunk.EvalDuration != 0 {
			return newError(providercontract.Conflict, "stream_partial_metrics", false)
		}
		if chunk.Message.Content == "" && chunk.Message.Thinking == "" && len(chunk.Message.ToolCalls) == 0 {
			return newError(providercontract.InvalidInput, "stream_partial_empty", false)
		}
		return nil
	}
	return reducer.finish(chunk)
}

func (reducer *streamReducer) accumulateMessage(message chatMessage) error {
	if message.Content != "" {
		if reducer.text.Len()+len(message.Content) > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_text_too_large", false)
		}
		reducer.text.WriteString(message.Content)
		if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "text_delta", TextDelta: message.Content}); err != nil {
			return err
		}
	}
	if message.Thinking != "" {
		if reducer.thinking.Len()+len(message.Thinking) > maximumResponseBytes {
			return newError(providercontract.Denied, "stream_thinking_too_large", false)
		}
		reducer.thinking.WriteString(message.Thinking)
	}
	for _, call := range message.ToolCalls {
		if call.Function.Index == nil {
			return newError(providercontract.InvalidInput, "stream_tool_index_missing", false)
		}
		index := *call.Function.Index
		if index != uint64(len(reducer.toolCalls)) {
			return newError(providercontract.Conflict, "stream_tool_index", false)
		}
		if _, exists := reducer.toolCalls[index]; exists {
			return newError(providercontract.Conflict, "stream_tool_duplicate", false)
		}
		if _, exists := reducer.tools[call.Function.Name]; !exists {
			return newError(providercontract.Denied, "stream_function_not_allowed", false)
		}
		reducer.toolCalls[index] = call
	}
	return nil
}

func (reducer *streamReducer) finish(chunk chatResponse) error {
	if chunk.DoneReason != "stop" && chunk.DoneReason != "length" || chunk.TotalDuration == 0 ||
		chunk.PromptEvalCount == 0 || chunk.PromptEvalCount > reducer.adapter.config.Capability.Value().Limits.MaximumInputTokens ||
		chunk.EvalCount > reducer.request.MaximumOutputTokens ||
		chunk.PromptEvalCount+chunk.EvalCount > reducer.request.Provider.ContextLimit {
		return newError(providercontract.Denied, "stream_terminal_binding", false)
	}
	indices := make([]int, 0, len(reducer.toolCalls))
	for index := range reducer.toolCalls {
		indices = append(indices, int(index))
	}
	sort.Ints(indices)
	calls := make([]nativeToolCall, 0, len(indices))
	for ordinal, index := range indices {
		if ordinal != index {
			return newError(providercontract.Conflict, "stream_tool_index", false)
		}
		calls = append(calls, reducer.toolCalls[uint64(index)])
	}
	chunk.Message = chatMessage{Role: "assistant", Content: reducer.text.String(), Thinking: reducer.thinking.String(), ToolCalls: calls}
	response, err := reducer.adapter.translateResponse(reducer.ctx, reducer.validatedRequest, reducer.request,
		reducer.tools, chunk, bytes.TrimSuffix(reducer.trace.Bytes(), []byte{'\n'}))
	if err != nil {
		return err
	}
	for _, item := range response.Value().Items {
		copy := item
		if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "item", Item: &copy}); err != nil {
			return err
		}
	}
	value := response.Value()
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
