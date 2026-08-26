package openairesponses

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type streamItemState struct {
	id        string
	kind      string
	done      bool
	canonical []byte
}

type streamReducer struct {
	adapter          *Adapter
	ctx              context.Context
	validatedRequest providercontract.ValidatedRequest
	request          providercontract.InferenceRequest
	tools            map[string]providercontract.Tool
	emit             StreamEmitter
	vendorStarted    bool
	vendorNext       uint64
	cohNext          uint64
	nextOutput       uint64
	responseID       string
	items            map[uint64]*streamItemState
	text             map[string]string
	arguments        map[string]string
	summaries        map[string]string
	refusals         map[string]string
	terminal         bool
}

func newStreamReducer(adapter *Adapter, ctx context.Context, validated providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, emit StreamEmitter) *streamReducer {
	return &streamReducer{adapter: adapter, ctx: ctx, validatedRequest: validated, request: request, tools: tools, emit: emit,
		items: make(map[uint64]*streamItemState), text: make(map[string]string), arguments: make(map[string]string),
		summaries: make(map[string]string), refusals: make(map[string]string)}
}

func (reducer *streamReducer) consume(raw []byte, header streamHeader) error {
	if reducer.terminal {
		return newError(providercontract.Conflict, "stream_after_terminal", false)
	}
	if !reducer.vendorStarted {
		if header.SequenceNumber > 1 {
			return newError(providercontract.Conflict, "vendor_stream_sequence", false)
		}
		reducer.vendorStarted = true
	} else if header.SequenceNumber != reducer.vendorNext {
		return newError(providercontract.Conflict, "vendor_stream_sequence", false)
	}
	reducer.vendorNext = header.SequenceNumber + 1
	switch header.Type {
	case "response.created", "response.in_progress":
		return reducer.responseProgress(raw, header.Type)
	case "response.output_item.added":
		return reducer.itemAdded(raw)
	case "response.output_item.done":
		return reducer.itemDone(raw)
	case "response.content_part.added", "response.content_part.done":
		return reducer.contentPart(raw)
	case "response.output_text.delta":
		return reducer.textDelta(raw)
	case "response.output_text.done":
		return reducer.textDone(raw)
	case "response.function_call_arguments.delta":
		return reducer.functionDelta(raw)
	case "response.function_call_arguments.done":
		return reducer.functionDone(raw)
	case "response.reasoning_summary_part.added", "response.reasoning_summary_part.done":
		return reducer.summaryPart(raw)
	case "response.reasoning_summary_text.delta":
		return reducer.summaryDelta(raw)
	case "response.reasoning_summary_text.done":
		return reducer.summaryDone(raw)
	case "response.refusal.delta":
		return reducer.refusalDelta(raw)
	case "response.refusal.done":
		return reducer.refusalDone(raw)
	case "response.completed", "response.failed", "response.incomplete":
		return reducer.responseTerminal(raw, header.Type)
	case "error":
		return reducer.errorTerminal(raw)
	default:
		return newError(providercontract.Unsupported, "vendor_stream_event_unknown", false)
	}
}

func (reducer *streamReducer) responseProgress(raw []byte, eventType string) error {
	var event streamResponseEvent
	if err := decodeExact(raw, &event); err != nil || event.Type != eventType || event.Response.Status != "in_progress" ||
		len(event.Response.Output) != 0 || reducer.validateStreamResponse(event.Response) != nil {
		return newError(providercontract.InvalidInput, "stream_progress_invalid", false)
	}
	if reducer.responseID == "" {
		reducer.responseID = event.Response.ID
	} else if reducer.responseID != event.Response.ID {
		return newError(providercontract.Conflict, "stream_response_identity", false)
	}
	return nil
}

func (reducer *streamReducer) itemAdded(raw []byte) error {
	var event streamItemEvent
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.output_item.added" ||
		event.OutputIndex != reducer.nextOutput {
		return newError(providercontract.Conflict, "stream_output_index", false)
	}
	id, kind, err := itemIdentity(event.Item)
	if err != nil || !supportedOutputKind(kind) {
		return newError(providercontract.Unsupported, "stream_output_item", false)
	}
	reducer.items[event.OutputIndex] = &streamItemState{id: id, kind: kind}
	reducer.nextOutput++
	return nil
}

func (reducer *streamReducer) itemDone(raw []byte) error {
	var event streamItemEvent
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.output_item.done" {
		return newError(providercontract.InvalidInput, "stream_output_done", false)
	}
	state := reducer.items[event.OutputIndex]
	id, kind, err := itemIdentity(event.Item)
	if state == nil || state.done || err != nil || state.id != id || state.kind != kind {
		return newError(providercontract.Conflict, "stream_output_correlation", false)
	}
	canonical, err := canonicalJSON(event.Item)
	if err != nil {
		return err
	}
	mapped, err := reducer.adapter.translateOutput(reducer.ctx, reducer.request, reducer.tools, []json.RawMessage{canonical})
	if err != nil {
		return err
	}
	for _, item := range mapped.items {
		copy := item
		if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "item", Item: &copy}); err != nil {
			return err
		}
	}
	state.done, state.canonical = true, canonical
	return nil
}

func (reducer *streamReducer) contentPart(raw []byte) error {
	var event streamContentEvent
	if err := decodeExact(raw, &event); err != nil || !reducer.correlated(event.OutputIndex, event.ItemID, "message") {
		return newError(providercontract.Conflict, "stream_content_correlation", false)
	}
	kind, err := peekType(event.Part)
	if err != nil || kind != "output_text" && kind != "refusal" {
		return newError(providercontract.Unsupported, "stream_content_part", false)
	}
	return nil
}

func (reducer *streamReducer) textDelta(raw []byte) error {
	var event streamTextDelta
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.output_text.delta" || len(event.Logprobs) != 0 ||
		!validOpaqueID(event.Delta, 1<<20) || !reducer.correlated(event.OutputIndex, event.ItemID, "message") {
		return newError(providercontract.Conflict, "stream_text_delta", false)
	}
	key := partKey(event.ItemID, event.ContentIndex)
	reducer.text[key] += event.Delta
	return reducer.emitCOH(providercontract.StreamEvent{Kind: "text_delta", TextDelta: event.Delta})
}

func (reducer *streamReducer) textDone(raw []byte) error {
	var event streamTextDone
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.output_text.done" || len(event.Logprobs) != 0 ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "message") || reducer.text[partKey(event.ItemID, event.ContentIndex)] != event.Text {
		return newError(providercontract.Conflict, "stream_text_done", false)
	}
	return nil
}

func (reducer *streamReducer) functionDelta(raw []byte) error {
	var event streamFunctionDelta
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.function_call_arguments.delta" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "function_call") {
		return newError(providercontract.Conflict, "stream_function_delta", false)
	}
	reducer.arguments[event.ItemID] += event.Delta
	if len(reducer.arguments[event.ItemID]) > 1<<20 {
		return newError(providercontract.Denied, "stream_function_size", false)
	}
	return nil
}

func (reducer *streamReducer) functionDone(raw []byte) error {
	var event streamFunctionDone
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.function_call_arguments.done" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "function_call") || reducer.arguments[event.ItemID] != event.Arguments {
		return newError(providercontract.Conflict, "stream_function_done", false)
	}
	if _, exists := reducer.tools[event.Name]; !exists {
		return newError(providercontract.Denied, "stream_function_not_allowed", false)
	}
	return nil
}

func (reducer *streamReducer) summaryPart(raw []byte) error {
	var event streamSummaryPartEvent
	if err := decodeExact(raw, &event); err != nil || !reducer.correlated(event.OutputIndex, event.ItemID, "reasoning") {
		return newError(providercontract.Conflict, "stream_summary_part", false)
	}
	kind, err := peekType(event.Part)
	if err != nil || kind != "summary_text" {
		return newError(providercontract.Unsupported, "stream_summary_part", false)
	}
	return nil
}

func (reducer *streamReducer) summaryDelta(raw []byte) error {
	var event streamSummaryDelta
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.reasoning_summary_text.delta" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "reasoning") {
		return newError(providercontract.Conflict, "stream_summary_delta", false)
	}
	reducer.summaries[partKey(event.ItemID, event.SummaryIndex)] += event.Delta
	return nil
}

func (reducer *streamReducer) summaryDone(raw []byte) error {
	var event streamSummaryDone
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.reasoning_summary_text.done" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "reasoning") ||
		reducer.summaries[partKey(event.ItemID, event.SummaryIndex)] != event.Text {
		return newError(providercontract.Conflict, "stream_summary_done", false)
	}
	return nil
}

func (reducer *streamReducer) refusalDelta(raw []byte) error {
	var event streamRefusalDelta
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.refusal.delta" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "message") {
		return newError(providercontract.Conflict, "stream_refusal_delta", false)
	}
	reducer.refusals[partKey(event.ItemID, event.ContentIndex)] += event.Delta
	return nil
}

func (reducer *streamReducer) refusalDone(raw []byte) error {
	var event streamRefusalDone
	if err := decodeExact(raw, &event); err != nil || event.Type != "response.refusal.done" ||
		!reducer.correlated(event.OutputIndex, event.ItemID, "message") ||
		reducer.refusals[partKey(event.ItemID, event.ContentIndex)] != event.Refusal {
		return newError(providercontract.Conflict, "stream_refusal_done", false)
	}
	return nil
}

func (reducer *streamReducer) responseTerminal(raw []byte, eventType string) error {
	var event streamResponseEvent
	if err := decodeExact(raw, &event); err != nil || event.Type != eventType || reducer.validateStreamResponse(event.Response) != nil ||
		reducer.responseID != event.Response.ID || !terminalTypeMatches(eventType, event.Response.Status) ||
		len(event.Response.Output) != len(reducer.items) {
		return newError(providercontract.Conflict, "stream_terminal_binding", false)
	}
	for index, item := range event.Response.Output {
		state := reducer.items[uint64(index)]
		canonical, err := canonicalJSON(item)
		if err != nil || state == nil || !state.done || !bytes.Equal(canonical, state.canonical) {
			return newError(providercontract.Conflict, "stream_terminal_output", false)
		}
	}
	encoded, _ := json.Marshal(event.Response)
	response, err := reducer.adapter.translateResponse(reducer.ctx, reducer.validatedRequest, reducer.request, reducer.tools, encoded)
	if err != nil {
		return err
	}
	value := response.Value()
	if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "completed", Response: &value}); err != nil {
		return err
	}
	reducer.terminal = true
	return nil
}

func (reducer *streamReducer) errorTerminal(raw []byte) error {
	var event streamError
	if err := decodeExact(raw, &event); err != nil || event.Type != "error" || !validOpaqueID(event.Message, 4096) {
		return newError(providercontract.InvalidInput, "stream_error_invalid", false)
	}
	terminal := providercontract.TerminalError{Code: "unavailable", Reason: "vendor_stream_error",
		Message: "model response stream failed", Retryable: true}
	if err := reducer.emitCOH(providercontract.StreamEvent{Kind: "error", Error: &terminal}); err != nil {
		return err
	}
	reducer.terminal = true
	return nil
}

func (reducer *streamReducer) validateStreamResponse(response createResponse) error {
	if !validOpaqueID(response.ID, 256) || response.Object != "response" || response.CreatedAt <= 0 ||
		response.Model != reducer.request.Provider.ActualModel || response.Background || response.Store ||
		response.Truncation != "disabled" || response.PreviousResponseID != nil || response.ParallelToolCalls {
		return newError(providercontract.Denied, "stream_response_binding", false)
	}
	return nil
}

func (reducer *streamReducer) emitCOH(event providercontract.StreamEvent) error {
	event.SchemaVersion, event.ContractVersion = providercontract.StreamEventSchemaVersion, providercontract.ContractVersion
	event.RequestID, event.AttemptID, event.Sequence = reducer.request.RequestID, reducer.request.AttemptID, reducer.cohNext
	event.ObservedAt = formatTimestamp(reducer.adapter.config.Clock())
	encoded, _ := json.Marshal(event)
	validated, err := providercontract.DecodeStreamEvent(reducer.ctx, encoded)
	if err != nil {
		return newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	if err := reducer.emit(validated); err != nil {
		return newError(providercontract.Unavailable, "stream_emitter_failed", false)
	}
	reducer.cohNext++
	return nil
}

func (reducer *streamReducer) correlated(index uint64, id, kind string) bool {
	state := reducer.items[index]
	return state != nil && !state.done && state.id == id && state.kind == kind
}

func itemIdentity(raw []byte) (string, string, error) {
	var common struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &common); err != nil || !validOpaqueID(common.ID, 256) || common.Type == "" {
		return "", "", newError(providercontract.InvalidInput, "stream_item_identity", false)
	}
	return common.ID, common.Type, nil
}

func supportedOutputKind(kind string) bool {
	return kind == "message" || kind == "function_call" || kind == "reasoning"
}

func partKey(id string, index uint64) string { return fmt.Sprintf("%s\x00%d", id, index) }

func terminalTypeMatches(eventType, status string) bool {
	return eventType == "response.completed" && status == "completed" || eventType == "response.failed" && status == "failed" ||
		eventType == "response.incomplete" && status == "incomplete"
}
