package llamacpp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const responseProvenanceDomain = "COH-LLAMACPP-RESPONSE-PROVENANCE-V1\x00"

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
	choice, err := adapter.validateResponseSurface(request, vendor)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	items, calls, err := adapter.mapMessage(ctx, request, tools, choice.Message)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if calls > adapter.config.Capability.Value().Limits.MaximumParallelToolCalls {
		return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "parallel_tool_limit", false)
	}
	outcome, terminal, err := terminalOutcome(choice.FinishReason)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	completed := time.Unix(vendor.Created, 0).UTC()
	duration := time.Duration(vendor.Timings.PromptMilliseconds+vendor.Timings.PredictedMilliseconds) * time.Millisecond
	if completed.IsZero() || duration <= 0 {
		return providercontract.ValidatedResponse{}, newError(providercontract.InvalidInput, "vendor_timing_invalid", false)
	}
	usageValue := providercontract.Usage{InputTokens: vendor.Usage.PromptTokens,
		OutputTokens: vendor.Usage.CompletionTokens, TotalTokens: vendor.Usage.TotalTokens}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion,
		ContractVersion: providercontract.ContractVersion,
		ResponseID:      deterministicUUID("COH-LLAMACPP-RESPONSE-ID-V1\x00", validatedRequest.Digest()+"\x00"+string(canonical)),
		RequestID:       request.RequestID, AttemptID: request.AttemptID, Provider: request.Provider,
		CapabilityDigest: request.CapabilityDigest, QualificationID: request.QualificationID, Outcome: outcome,
		Items: items, Usage: usageValue, State: providercontract.State{Mode: "stateless"},
		StartedAt: formatTimestamp(completed.Add(-duration)), CompletedAt: formatTimestamp(completed),
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

func (adapter *Adapter) validateResponseSurface(request providercontract.InferenceRequest, response chatResponse) (chatChoice, error) {
	runtimeVersion, runtimeErr := normalizeBuildInfo(response.SystemFingerprint)
	if !validText(response.ID, 128) || !strings.HasPrefix(response.ID, "chatcmpl-") || response.Object != "chat.completion" ||
		response.Created <= 0 || response.Model != request.Provider.ActualModel ||
		runtimeErr != nil || runtimeVersion != request.Provider.RuntimeVersion || len(response.Choices) != 1 {
		return chatChoice{}, newError(providercontract.Denied, "vendor_response_binding", false)
	}
	choice := response.Choices[0]
	if choice.Index != 0 || choice.Message.Role != "assistant" || len(choice.Logprobs) != 0 ||
		response.Usage.PromptTokens == 0 || response.Usage.PromptTokens > adapter.config.Capability.Value().Limits.MaximumInputTokens ||
		response.Usage.CompletionTokens > request.MaximumOutputTokens ||
		response.Usage.TotalTokens != response.Usage.PromptTokens+response.Usage.CompletionTokens ||
		response.Usage.TotalTokens > request.Provider.ContextLimit ||
		response.Timings.PromptTokens+response.Timings.CacheTokens != response.Usage.PromptTokens ||
		response.Timings.PredictedTokens != response.Usage.CompletionTokens ||
		response.Timings.PromptMilliseconds <= 0 || response.Timings.PredictedMilliseconds <= 0 {
		return chatChoice{}, newError(providercontract.Denied, "vendor_response_binding", false)
	}
	if choice.FinishReason != "stop" && choice.FinishReason != "length" && choice.FinishReason != "tool_calls" {
		return chatChoice{}, newError(providercontract.Unsupported, "vendor_finish_reason", false)
	}
	if choice.Message.Content == "" && choice.Message.ReasoningContent == "" && len(choice.Message.ToolCalls) == 0 {
		return chatChoice{}, newError(providercontract.InvalidInput, "vendor_response_empty", false)
	}
	return choice, nil
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
	if message.ReasoningContent != "" {
		envelope, err := json.Marshal(reasoningEnvelope{ReasoningContent: message.ReasoningContent})
		if err != nil {
			return nil, 0, newError(providercontract.Internal, "reasoning_encoding", false)
		}
		canonical, err := canonicalJSON(envelope)
		if err != nil {
			return nil, 0, err
		}
		reasoningDigest := digest(reasoningDigestDomain, canonical)
		referenceID := deterministicUUID("COH-LLAMACPP-REASONING-ID-V1\x00", request.RequestID+"\x00"+reasoningDigest)
		if err := adapter.config.Reasoning.Put(ctx, referenceID, reasoningDigest, canonical); err != nil {
			return nil, 0, newError(providercontract.Unavailable, "reasoning_persistence_failed", true)
		}
		items = append(items, providercontract.ContentItem{Kind: "reasoning_ref", ReferenceID: referenceID, Digest: reasoningDigest})
	}
	seenIDs := make(map[string]struct{}, len(message.ToolCalls))
	for ordinal, call := range message.ToolCalls {
		if !validText(call.ID, 128) {
			return nil, 0, newError(providercontract.InvalidInput, "vendor_tool_id", false)
		}
		if _, duplicate := seenIDs[call.ID]; duplicate {
			return nil, 0, newError(providercontract.Conflict, "vendor_tool_id_duplicate", false)
		}
		seenIDs[call.ID] = struct{}{}
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
	if call.Type != "function" {
		return providercontract.ContentItem{}, newError(providercontract.Unsupported, "vendor_tool_type", false)
	}
	if call.Index != nil && *call.Index != uint64(ordinal) {
		return providercontract.ContentItem{}, newError(providercontract.Conflict, "vendor_tool_index", false)
	}
	tool, exists := tools[call.Function.Name]
	canonical, err := canonicalJSON([]byte(call.Function.Arguments))
	if !exists || err != nil || !jsonObject(canonical) {
		return providercontract.ContentItem{}, newError(providercontract.Denied, "vendor_function_not_allowed", false)
	}
	callID := fmt.Sprintf("llamacpp:%s:%d", request.RequestID, ordinal)
	return providercontract.ContentItem{Kind: "tool_call", CallID: callID, ToolName: tool.Name,
		Arguments: canonical, InputSchemaDigest: tool.InputSchemaDigest}, nil
}

func terminalOutcome(reason string) (string, *providercontract.TerminalError, error) {
	switch reason {
	case "stop", "tool_calls":
		return "succeeded", nil, nil
	case "length":
		return "uncertain", &providercontract.TerminalError{Code: "unavailable", Reason: "response_incomplete",
			Message: "model response reached its output limit"}, nil
	default:
		return "", nil, newError(providercontract.Unsupported, "vendor_finish_reason", false)
	}
}
