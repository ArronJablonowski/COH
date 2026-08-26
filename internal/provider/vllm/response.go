package vllm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const responseProvenanceDomain = "COH-VLLM-RESPONSE-PROVENANCE-V1\x00"

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
	started := adapter.config.Clock().UTC()
	if started.IsZero() {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "clock_unavailable", false)
	}
	if err := adapter.verifyIdentity(requestContext, requestValue.Provider.RequestedModel); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	var vendor chatResponse
	canonical, err := adapter.postJSON(requestContext, ChatPath, translation.wire, &vendor)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	completed := adapter.config.Clock().UTC()
	return adapter.translateResponse(requestContext, request, requestValue, translation.tools, vendor, canonical, started, completed)
}

func (adapter *Adapter) translateResponse(ctx context.Context, validatedRequest providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, vendor chatResponse,
	canonical []byte, started, completed time.Time) (providercontract.ValidatedResponse, error) {
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
	outcome, terminal, err := terminalOutcome(*choice.FinishReason)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if started.IsZero() || completed.IsZero() || completed.Before(started) {
		return providercontract.ValidatedResponse{}, newError(providercontract.Internal, "clock_invalid", false)
	}
	completion := *vendor.Usage.CompletionTokens
	cached, reasoning := uint64(0), uint64(0)
	if vendor.Usage.PromptTokensDetails != nil && vendor.Usage.PromptTokensDetails.CachedTokens != nil {
		cached = *vendor.Usage.PromptTokensDetails.CachedTokens
	}
	if vendor.Usage.CompletionTokensDetails != nil {
		reasoning = vendor.Usage.CompletionTokensDetails.ReasoningTokens
	}
	usageValue := providercontract.Usage{InputTokens: vendor.Usage.PromptTokens, OutputTokens: completion,
		TotalTokens: vendor.Usage.TotalTokens, CachedInputTokens: cached, ReasoningTokens: reasoning}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion,
		ContractVersion: providercontract.ContractVersion,
		ResponseID:      deterministicUUID("COH-VLLM-RESPONSE-ID-V1\x00", validatedRequest.Digest()+"\x00"+string(canonical)),
		RequestID:       request.RequestID, AttemptID: request.AttemptID, Provider: request.Provider,
		CapabilityDigest: request.CapabilityDigest, QualificationID: request.QualificationID, Outcome: outcome,
		Items: items, Usage: usageValue, State: providercontract.State{Mode: "stateless"},
		StartedAt: formatTimestamp(started), CompletedAt: formatTimestamp(completed),
		ProvenanceDigest: digest(responseProvenanceDomain, append([]byte(validatedRequest.Digest()+"\x00"+request.CapabilityDigest+"\x00"), canonical...)), Error: terminal}
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
	if !validText(response.ID, 128) || !strings.HasPrefix(response.ID, "chatcmpl-") || response.Object != "chat.completion" || response.Created <= 0 ||
		response.Model != request.Provider.ActualModel || response.SystemFingerprint == nil || *response.SystemFingerprint != request.Provider.RuntimeDigest || len(response.Choices) != 1 ||
		!nullJSON(response.ServiceTier) || !nullJSON(response.PromptLogprobs) || !nullJSON(response.PromptTokenIDs) || !nullJSON(response.PromptText) ||
		!nullJSON(response.KVTransferParams) || !nullJSON(response.ECTransferParams) || !nullJSON(response.Metrics) || response.Usage.CompletionTokens == nil {
		return chatChoice{}, newError(providercontract.Denied, "vendor_response_binding", false)
	}
	choice := response.Choices[0]
	completion := *response.Usage.CompletionTokens
	if choice.Index != 0 || choice.Message.Role != "assistant" || choice.FinishReason == nil || !nullJSON(choice.Logprobs) || !nullJSON(choice.StopReason) || !nullJSON(choice.TokenIDs) || !nullJSON(choice.RoutedExperts) ||
		!nullJSON(choice.Message.Refusal) || !nullJSON(choice.Message.Annotations) || !nullJSON(choice.Message.Audio) || !nullJSON(choice.Message.FunctionCall) ||
		response.Usage.PromptTokens == 0 || response.Usage.PromptTokens > adapter.config.Capability.Value().Limits.MaximumInputTokens || completion > request.MaximumOutputTokens ||
		response.Usage.TotalTokens != response.Usage.PromptTokens+completion || response.Usage.TotalTokens > request.Provider.ContextLimit {
		return chatChoice{}, newError(providercontract.Denied, "vendor_response_binding", false)
	}
	if response.Usage.PromptTokensDetails != nil {
		details := response.Usage.PromptTokensDetails
		if details.CreatedCacheTokens != nil && *details.CreatedCacheTokens != 0 || !nullJSON(details.MultimodalTokens) || details.CachedTokens != nil && *details.CachedTokens > response.Usage.PromptTokens {
			return chatChoice{}, newError(providercontract.Denied, "vendor_usage_invalid", false)
		}
	}
	if response.Usage.CompletionTokensDetails != nil && response.Usage.CompletionTokensDetails.ReasoningTokens > completion {
		return chatChoice{}, newError(providercontract.Denied, "vendor_usage_invalid", false)
	}
	if *choice.FinishReason != "stop" && *choice.FinishReason != "length" && *choice.FinishReason != "tool_calls" {
		return chatChoice{}, newError(providercontract.Unsupported, "vendor_finish_reason", false)
	}
	if (choice.Message.Content == nil || *choice.Message.Content == "") && (choice.Message.Reasoning == nil || *choice.Message.Reasoning == "") && len(choice.Message.ToolCalls) == 0 {
		return chatChoice{}, newError(providercontract.InvalidInput, "vendor_response_empty", false)
	}
	return choice, nil
}

func nullJSON(value json.RawMessage) bool {
	return len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func (adapter *Adapter) mapMessage(ctx context.Context, request providercontract.InferenceRequest,
	tools map[string]providercontract.Tool, message responseMessage) ([]providercontract.ContentItem, uint16, error) {
	items := make([]providercontract.ContentItem, 0, 2+len(message.ToolCalls))
	if message.Content != nil && *message.Content != "" {
		if request.OutputConstraint.Kind == "json_schema" {
			canonical, err := canonicalJSON([]byte(*message.Content))
			if err != nil || !jsonObject(canonical) {
				return nil, 0, newError(providercontract.InvalidInput, "structured_output_invalid", false)
			}
			items = append(items, providercontract.ContentItem{Kind: "output_json", Value: canonical, SchemaDigest: request.OutputConstraint.SchemaDigest})
		} else {
			items = append(items, providercontract.ContentItem{Kind: "text", Text: *message.Content})
		}
	}
	if message.Reasoning != nil && *message.Reasoning != "" {
		envelope, err := json.Marshal(reasoningEnvelope{Reasoning: *message.Reasoning})
		if err != nil {
			return nil, 0, newError(providercontract.Internal, "reasoning_encoding", false)
		}
		canonical, err := canonicalJSON(envelope)
		if err != nil {
			return nil, 0, err
		}
		reasoningDigest := digest(reasoningDigestDomain, canonical)
		referenceID := deterministicUUID("COH-VLLM-REASONING-ID-V1\x00", request.RequestID+"\x00"+reasoningDigest)
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

func mapToolCall(request providercontract.InferenceRequest, tools map[string]providercontract.Tool, call nativeToolCall, ordinal int) (providercontract.ContentItem, error) {
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
	callID := fmt.Sprintf("vllm:%s:%d", request.RequestID, ordinal)
	return providercontract.ContentItem{Kind: "tool_call", CallID: callID, ToolName: tool.Name, Arguments: canonical, InputSchemaDigest: tool.InputSchemaDigest}, nil
}

func terminalOutcome(reason string) (string, *providercontract.TerminalError, error) {
	switch reason {
	case "stop", "tool_calls":
		return "succeeded", nil, nil
	case "length":
		return "uncertain", &providercontract.TerminalError{Code: "unavailable", Reason: "response_incomplete", Message: "model response reached its output limit"}, nil
	default:
		return "", nil, newError(providercontract.Unsupported, "vendor_finish_reason", false)
	}
}
