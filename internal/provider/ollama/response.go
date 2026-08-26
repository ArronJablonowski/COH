package ollama

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const responseProvenanceDomain = "COH-OLLAMA-RESPONSE-PROVENANCE-V1\x00"

func (adapter *Adapter) Invoke(ctx context.Context, request providercontract.ValidatedRequest) (providercontract.ValidatedResponse, error) {
	requestValue, timeout, err := adapter.validateDispatch(ctx, request)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	translation, err := adapter.translateRequest(ctx, requestValue)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := adapter.verifyIdentity(requestContext, requestValue.Provider.RequestedModel); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	var vendor chatResponse
	canonical, err := adapter.postJSON(requestContext, ChatPath, translation.wire, &vendor)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	return adapter.translateResponse(requestContext, request, requestValue, translation.tools, vendor, canonical)
}

func (adapter *Adapter) translateResponse(ctx context.Context, validatedRequest providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, vendor chatResponse,
	canonical []byte) (providercontract.ValidatedResponse, error) {
	if err := adapter.validateResponseSurface(request, vendor); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	items, calls, err := adapter.mapMessage(ctx, request, tools, vendor.Message)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if calls > adapter.config.Capability.Value().Limits.MaximumParallelToolCalls {
		return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "parallel_tool_limit", false)
	}
	outcome, terminal, err := terminalOutcome(vendor.DoneReason)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	completed, err := time.Parse(time.RFC3339Nano, vendor.CreatedAt)
	if err != nil || vendor.TotalDuration == 0 {
		return providercontract.ValidatedResponse{}, newError(providercontract.InvalidInput, "vendor_timing_invalid", false)
	}
	started := completed.Add(-time.Duration(vendor.TotalDuration))
	usage := providercontract.Usage{InputTokens: vendor.PromptEvalCount, OutputTokens: vendor.EvalCount,
		TotalTokens: vendor.PromptEvalCount + vendor.EvalCount}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion,
		ContractVersion: providercontract.ContractVersion,
		ResponseID:      deterministicUUID("COH-OLLAMA-RESPONSE-ID-V1\x00", validatedRequest.Digest()+"\x00"+string(canonical)),
		RequestID:       request.RequestID, AttemptID: request.AttemptID, Provider: request.Provider,
		CapabilityDigest: request.CapabilityDigest, QualificationID: request.QualificationID, Outcome: outcome,
		Items: items, Usage: usage, State: providercontract.State{Mode: "stateless"},
		StartedAt: formatTimestamp(started), CompletedAt: formatTimestamp(completed),
		ProvenanceDigest: digest(responseProvenanceDomain,
			append([]byte(validatedRequest.Digest()+"\x00"+request.CapabilityDigest+"\x00"), canonical...)), Error: terminal}
	encoded, err := json.Marshal(response)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "response_encoding", false)
	}
	validated, err := providercontract.DecodeResponse(ctx, encoded)
	if err != nil {
		return providercontract.ValidatedResponse{}, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	return validated, nil
}

func (adapter *Adapter) validateResponseSurface(request providercontract.InferenceRequest, response chatResponse) error {
	if response.Model != request.Provider.ActualModel || !response.Done || response.Message.Role != "assistant" ||
		len(response.Message.Images) != 0 || len(response.Logprobs) != 0 || response.PromptEvalCount == 0 ||
		response.PromptEvalCount > adapter.config.Capability.Value().Limits.MaximumInputTokens ||
		response.EvalCount > request.MaximumOutputTokens || response.PromptEvalCount+response.EvalCount > request.Provider.ContextLimit {
		return newError(providercontract.Denied, "vendor_response_binding", false)
	}
	if response.DoneReason != "stop" && response.DoneReason != "length" {
		return newError(providercontract.Unsupported, "vendor_done_reason", false)
	}
	if response.Message.Content == "" && response.Message.Thinking == "" && len(response.Message.ToolCalls) == 0 {
		return newError(providercontract.InvalidInput, "vendor_response_empty", false)
	}
	return nil
}

func (adapter *Adapter) mapMessage(ctx context.Context, request providercontract.InferenceRequest,
	tools map[string]providercontract.Tool, message chatMessage) ([]providercontract.ContentItem, uint16, error) {
	items := make([]providercontract.ContentItem, 0, 2+len(message.ToolCalls))
	if message.Content != "" {
		if request.OutputConstraint.Kind == "json_schema" {
			canonical, err := canonicalJSON([]byte(message.Content))
			if err != nil || !jsonObject(canonical) {
				return nil, 0, newError(providercontract.InvalidInput, "structured_output_invalid", false)
			}
			items = append(items, providercontract.ContentItem{Kind: "output_json", Value: canonical,
				SchemaDigest: request.OutputConstraint.SchemaDigest})
		} else {
			items = append(items, providercontract.ContentItem{Kind: "text", Text: message.Content})
		}
	}
	if message.Thinking != "" {
		envelope, err := json.Marshal(thinkingEnvelope{Thinking: message.Thinking})
		if err != nil {
			return nil, 0, newError(providercontract.Internal, "reasoning_encoding", false)
		}
		canonical, err := canonicalJSON(envelope)
		if err != nil {
			return nil, 0, err
		}
		reasoningDigest := digest(thinkingDigestDomain, canonical)
		referenceID := deterministicUUID("COH-OLLAMA-THINKING-ID-V1\x00", request.RequestID+"\x00"+reasoningDigest)
		if err := adapter.config.Reasoning.Put(ctx, referenceID, reasoningDigest, canonical); err != nil {
			return nil, 0, newError(providercontract.Unavailable, "reasoning_persistence_failed", true)
		}
		items = append(items, providercontract.ContentItem{Kind: "reasoning_ref", ReferenceID: referenceID, Digest: reasoningDigest})
	}
	for ordinal, call := range message.ToolCalls {
		item, err := mapToolCall(request, tools, call, ordinal)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, uint16(len(message.ToolCalls)), nil
}

func mapToolCall(request providercontract.InferenceRequest, tools map[string]providercontract.Tool,
	call nativeToolCall, ordinal int) (providercontract.ContentItem, error) {
	if call.Type != "" && call.Type != "function" {
		return providercontract.ContentItem{}, newError(providercontract.Unsupported, "vendor_tool_type", false)
	}
	index := uint64(ordinal)
	if call.Function.Index != nil {
		index = *call.Function.Index
	}
	if index != uint64(ordinal) {
		return providercontract.ContentItem{}, newError(providercontract.Conflict, "vendor_tool_index", false)
	}
	tool, exists := tools[call.Function.Name]
	canonical, err := canonicalJSON(call.Function.Arguments)
	if !exists || err != nil || !jsonObject(canonical) {
		return providercontract.ContentItem{}, newError(providercontract.Denied, "vendor_function_not_allowed", false)
	}
	callID := fmt.Sprintf("ollama:%s:%d", request.RequestID, index)
	return providercontract.ContentItem{Kind: "tool_call", CallID: callID, ToolName: tool.Name,
		Arguments: canonical, InputSchemaDigest: tool.InputSchemaDigest}, nil
}

func terminalOutcome(reason string) (string, *providercontract.TerminalError, error) {
	switch reason {
	case "stop":
		return "succeeded", nil, nil
	case "length":
		return "uncertain", &providercontract.TerminalError{Code: "unavailable", Reason: "response_incomplete",
			Message: "model response reached its output limit"}, nil
	default:
		return "", nil, newError(providercontract.Unsupported, "vendor_done_reason", false)
	}
}
