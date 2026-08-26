package openairesponses

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const responseProvenanceDomain = "COH-OPENAI-RESPONSES-PROVENANCE-V1\x00"

type mappedItems struct {
	items          []providercontract.ContentItem
	refused        bool
	functionCalls  uint16
	reasoningItems uint16
}

func (adapter *Adapter) Invoke(ctx context.Context, request providercontract.ValidatedRequest) (providercontract.ValidatedResponse, error) {
	requestValue, deadline, err := adapter.validateDispatch(ctx, request)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	translation, err := adapter.translateRequest(ctx, requestValue)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	requestContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	body, err := adapter.post(requestContext, translation.wire)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	return adapter.translateResponse(requestContext, request, requestValue, translation.tools, body)
}

func (adapter *Adapter) translateResponse(ctx context.Context, validatedRequest providercontract.ValidatedRequest,
	request providercontract.InferenceRequest, tools map[string]providercontract.Tool, body []byte) (providercontract.ValidatedResponse, error) {
	var vendor createResponse
	canonicalBody, err := canonicalJSON(body)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if err := decodeExact(canonicalBody, &vendor); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if err := adapter.validateResponseSurface(request, vendor); err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	mapped, err := adapter.translateOutput(ctx, request, tools, vendor.Output)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	if mapped.functionCalls > adapter.config.Capability.Value().Limits.MaximumParallelToolCalls {
		return providercontract.ValidatedResponse{}, newError(providercontract.Denied, "parallel_tool_limit", false)
	}
	outcome, terminal, err := terminalOutcome(vendor, mapped.refused)
	if err != nil {
		return providercontract.ValidatedResponse{}, err
	}
	started := time.Unix(vendor.CreatedAt, 0).UTC()
	completed := adapter.config.Clock().UTC()
	if vendor.CompletedAt != nil {
		completed = time.Unix(*vendor.CompletedAt, 0).UTC()
	}
	if completed.Before(started) {
		return providercontract.ValidatedResponse{}, newError(providercontract.InvalidInput, "vendor_timing_invalid", false)
	}
	response := providercontract.InferenceResponse{SchemaVersion: providercontract.ResponseSchemaVersion,
		ContractVersion: providercontract.ContractVersion, ResponseID: responseUUID(vendor.ID), RequestID: request.RequestID,
		AttemptID: request.AttemptID, Provider: request.Provider, CapabilityDigest: request.CapabilityDigest,
		QualificationID: request.QualificationID, Outcome: outcome, Items: mapped.items, Usage: mapUsage(vendor.Usage),
		State: providercontract.State{Mode: "stateless"}, StartedAt: formatTimestamp(started), CompletedAt: formatTimestamp(completed),
		ProvenanceDigest: provenanceDigest(validatedRequest.Digest(), request.CapabilityDigest, canonicalBody), Error: terminal}
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

func (adapter *Adapter) validateResponseSurface(request providercontract.InferenceRequest, response createResponse) error {
	if !validOpaqueID(response.ID, 256) || response.Object != "response" || response.CreatedAt <= 0 ||
		response.Model != request.Provider.ActualModel || response.Background || response.Store ||
		response.Truncation != "disabled" || response.PreviousResponseID != nil || response.ParallelToolCalls {
		return newError(providercontract.Denied, "vendor_response_binding", false)
	}
	if response.MaxOutputTokens != nil && *response.MaxOutputTokens != request.MaximumOutputTokens {
		return newError(providercontract.Denied, "vendor_output_limit_drift", false)
	}
	switch response.Status {
	case "completed", "failed", "incomplete", "cancelled":
		return nil
	case "queued", "in_progress":
		return newError(providercontract.Conflict, "background_status_unexpected", false)
	default:
		return newError(providercontract.Unsupported, "vendor_status_unknown", false)
	}
}

func (adapter *Adapter) translateOutput(ctx context.Context, request providercontract.InferenceRequest,
	tools map[string]providercontract.Tool, output []json.RawMessage) (mappedItems, error) {
	result := mappedItems{items: make([]providercontract.ContentItem, 0, len(output))}
	for _, raw := range output {
		itemType, err := peekType(raw)
		if err != nil {
			return mappedItems{}, err
		}
		switch itemType {
		case "message":
			items, refused, err := mapMessage(raw, request.OutputConstraint)
			if err != nil {
				return mappedItems{}, err
			}
			result.items = append(result.items, items...)
			result.refused = result.refused || refused
		case "function_call":
			item, err := mapFunctionCall(raw, tools)
			if err != nil {
				return mappedItems{}, err
			}
			result.items = append(result.items, item)
			result.functionCalls++
		case "reasoning":
			item, err := adapter.mapReasoning(ctx, raw)
			if err != nil {
				return mappedItems{}, err
			}
			result.items = append(result.items, item)
			result.reasoningItems++
		default:
			return mappedItems{}, newError(providercontract.Unsupported, "vendor_output_item_unknown", false)
		}
	}
	return result, nil
}

func mapMessage(raw []byte, constraint providercontract.OutputConstraint) ([]providercontract.ContentItem, bool, error) {
	var message outputMessage
	if err := decodeExact(raw, &message); err != nil || message.Type != "message" || message.Role != "assistant" ||
		(message.Status != "completed" && message.Status != "incomplete") || !validOpaqueID(message.ID, 256) {
		return nil, false, newError(providercontract.InvalidInput, "vendor_message_invalid", false)
	}
	items := make([]providercontract.ContentItem, 0, len(message.Content))
	refused := false
	for _, rawContent := range message.Content {
		contentType, err := peekType(rawContent)
		if err != nil {
			return nil, false, err
		}
		switch contentType {
		case "output_text":
			var content outputText
			if err := decodeExact(rawContent, &content); err != nil || len(content.Annotations) != 0 || content.Text == "" {
				return nil, false, newError(providercontract.Unsupported, "vendor_output_text_invalid", false)
			}
			if constraint.Kind == "json_schema" {
				canonical, err := canonicalJSON([]byte(content.Text))
				if err != nil || !jsonObject(canonical) {
					return nil, false, newError(providercontract.InvalidInput, "structured_output_invalid", false)
				}
				items = append(items, providercontract.ContentItem{Kind: "output_json", Value: canonical, SchemaDigest: constraint.SchemaDigest})
			} else {
				items = append(items, providercontract.ContentItem{Kind: "text", Text: content.Text})
			}
		case "refusal":
			var content refusal
			if err := decodeExact(rawContent, &content); err != nil || !validOpaqueID(content.Refusal, 4096) {
				return nil, false, newError(providercontract.InvalidInput, "vendor_refusal_invalid", false)
			}
			refused = true
		default:
			return nil, false, newError(providercontract.Unsupported, "vendor_message_content_unknown", false)
		}
	}
	return items, refused, nil
}

func mapFunctionCall(raw []byte, tools map[string]providercontract.Tool) (providercontract.ContentItem, error) {
	var call functionCall
	if err := decodeExact(raw, &call); err != nil || call.Type != "function_call" || call.Status != "completed" ||
		!validOpaqueID(call.ID, 256) || !validOpaqueID(call.CallID, 128) {
		return providercontract.ContentItem{}, newError(providercontract.InvalidInput, "vendor_function_call_invalid", false)
	}
	tool, exists := tools[call.Name]
	canonical, err := canonicalJSON([]byte(call.Arguments))
	if !exists || err != nil || !jsonObject(canonical) {
		return providercontract.ContentItem{}, newError(providercontract.Denied, "vendor_function_not_allowed", false)
	}
	return providercontract.ContentItem{Kind: "tool_call", CallID: call.CallID, ToolName: call.Name,
		Arguments: canonical, InputSchemaDigest: tool.InputSchemaDigest}, nil
}

func (adapter *Adapter) mapReasoning(ctx context.Context, raw []byte) (providercontract.ContentItem, error) {
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return providercontract.ContentItem{}, err
	}
	var reasoning reasoningItem
	if err := decodeExact(canonical, &reasoning); err != nil || validateReasoning(reasoning) != nil {
		return providercontract.ContentItem{}, newError(providercontract.InvalidInput, "vendor_reasoning_invalid", false)
	}
	digest := digestReasoning(canonical)
	if err := adapter.config.Reasoning.Put(ctx, reasoning.ID, digest, canonical); err != nil {
		return providercontract.ContentItem{}, newError(providercontract.Unavailable, "reasoning_persistence_failed", true)
	}
	return providercontract.ContentItem{Kind: "reasoning_ref", ReferenceID: reasoning.ID, Digest: digest}, nil
}

func validateReasoning(value reasoningItem) error {
	if value.Type != "reasoning" || !validOpaqueID(value.ID, 256) ||
		(value.Status != "completed" && value.Status != "incomplete") || !validOpaqueID(value.EncryptedContent, 1<<20) {
		return newError(providercontract.InvalidInput, "vendor_reasoning_invalid", false)
	}
	for _, summary := range value.Summary {
		if summary.Type != "summary_text" || !validOpaqueID(summary.Text, 1<<20) {
			return newError(providercontract.InvalidInput, "vendor_reasoning_summary_invalid", false)
		}
	}
	return nil
}

func terminalOutcome(response createResponse, refused bool) (string, *providercontract.TerminalError, error) {
	if refused {
		return "denied", &providercontract.TerminalError{Code: "denied", Reason: "model_refusal", Message: "model refused the request"}, nil
	}
	switch response.Status {
	case "completed":
		if response.Error != nil || response.IncompleteDetails != nil {
			return "", nil, newError(providercontract.InvalidInput, "vendor_terminal_conflict", false)
		}
		return "succeeded", nil, nil
	case "failed":
		if response.Error == nil || response.IncompleteDetails != nil {
			return "", nil, newError(providercontract.InvalidInput, "vendor_failure_missing", false)
		}
		return "failed", &providercontract.TerminalError{Code: "unavailable", Reason: "vendor_failed", Message: "model response failed", Retryable: true}, nil
	case "incomplete":
		if response.IncompleteDetails == nil || response.Error != nil ||
			(response.IncompleteDetails.Reason != "max_output_tokens" && response.IncompleteDetails.Reason != "max_tokens" &&
				response.IncompleteDetails.Reason != "content_filter") {
			return "", nil, newError(providercontract.Unsupported, "vendor_incomplete_reason", false)
		}
		return "uncertain", &providercontract.TerminalError{Code: "unavailable", Reason: "response_incomplete", Message: "model response is incomplete"}, nil
	case "cancelled":
		if response.Error != nil || response.IncompleteDetails != nil {
			return "", nil, newError(providercontract.InvalidInput, "vendor_terminal_conflict", false)
		}
		return "canceled", &providercontract.TerminalError{Code: "canceled", Reason: "vendor_canceled", Message: "model response was canceled"}, nil
	default:
		return "", nil, newError(providercontract.Unsupported, "vendor_status_unknown", false)
	}
}

func mapUsage(value *vendorUsage) providercontract.Usage {
	if value == nil {
		return providercontract.Usage{}
	}
	usage := providercontract.Usage{InputTokens: value.InputTokens, OutputTokens: value.OutputTokens, TotalTokens: value.TotalTokens}
	if value.InputTokenDetails != nil {
		usage.CachedInputTokens = value.InputTokenDetails.CachedTokens
	}
	if value.OutputTokenDetails != nil {
		usage.ReasoningTokens = value.OutputTokenDetails.ReasoningTokens
	}
	return usage
}

func provenanceDigest(requestDigest, capabilityDigest string, canonical []byte) string {
	input := []byte(responseProvenanceDomain + requestDigest + "\x00" + capabilityDigest + "\x00")
	input = append(input, canonical...)
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func jsonObject(value []byte) bool {
	var object map[string]any
	return json.Unmarshal(value, &object) == nil && object != nil
}

func formatTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
