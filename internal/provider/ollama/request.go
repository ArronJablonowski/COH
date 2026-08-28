package ollama

import (
	"context"
	"encoding/json"
	"strings"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const thinkingDigestDomain = "COH-OLLAMA-THINKING-V1\x00"

type requestTranslation struct {
	wire  chatRequest
	tools map[string]providercontract.Tool
}

type thinkingEnvelope struct {
	Thinking string `json:"thinking"`
}

type toolResultEnvelope struct {
	Outcome string          `json:"outcome"`
	Value   json.RawMessage `json:"value"`
}

func (adapter *Adapter) translateRequest(ctx context.Context, request providercontract.InferenceRequest) (requestTranslation, error) {
	translation := requestTranslation{tools: make(map[string]providercontract.Tool, len(request.Tools))}
	contextLength := adapter.config.Capability.Value().Limits.MaximumInputTokens + adapter.config.Capability.Value().Limits.MaximumOutputTokens
	if contextLength > request.Provider.ContextLimit {
		contextLength = request.Provider.ContextLimit
	}
	translation.wire = chatRequest{Model: request.Provider.RequestedModel, Stream: false, Think: true, KeepAlive: 0,
		Options: chatOptions{ContextLength: contextLength, MaximumPredict: request.MaximumOutputTokens,
			Temperature: float64(request.Sampling.TemperatureMilli) / 1000,
			TopP:        float64(request.Sampling.TopPMillionths) / 1000000, Seed: request.Sampling.Seed}}
	for _, tool := range request.Tools {
		inputSchema, err := adapter.resolveSchema(ctx, tool.InputSchemaDigest)
		if err != nil {
			return requestTranslation{}, err
		}
		if _, err := adapter.resolveSchema(ctx, tool.OutputSchemaDigest); err != nil {
			return requestTranslation{}, err
		}
		translation.tools[tool.Name] = tool
		translation.wire.Tools = append(translation.wire.Tools, functionTool{Type: "function",
			Function: toolDefinition{Name: tool.Name, Description: tool.Description, Parameters: inputSchema}})
	}
	if request.OutputConstraint.Kind == "json_schema" {
		schema, err := adapter.resolveSchema(ctx, request.OutputConstraint.SchemaDigest)
		if err != nil {
			return requestTranslation{}, err
		}
		translation.wire.Format = schema
	}
	callTools := make(map[string]string)
	for _, message := range request.Messages {
		wire, err := adapter.translateMessage(ctx, message, translation.tools, callTools)
		if err != nil {
			return requestTranslation{}, err
		}
		translation.wire.Messages = append(translation.wire.Messages, wire)
	}
	return translation, nil
}

func (adapter *Adapter) translateMessage(ctx context.Context, message providercontract.Message,
	allowed map[string]providercontract.Tool, callTools map[string]string) (chatMessage, error) {
	if !contains(adapter.config.Capability.Value().Features.MessageRoles, message.Role) {
		return chatMessage{}, newError(providercontract.Unsupported, "message_role_not_supported", false)
	}
	wire := chatMessage{Role: message.Role}
	contentCount := 0
	for _, item := range message.Items {
		switch item.Kind {
		case "text":
			if contentCount > 0 {
				return chatMessage{}, newError(providercontract.Unsupported, "multiple_message_content", false)
			}
			wire.Content, contentCount = item.Text, contentCount+1
		case "input_json", "output_json":
			if contentCount > 0 {
				return chatMessage{}, newError(providercontract.Unsupported, "multiple_message_content", false)
			}
			canonical, err := canonicalJSON(item.Value)
			if err != nil {
				return chatMessage{}, err
			}
			wire.Content, contentCount = string(canonical), contentCount+1
		case "reasoning_ref":
			if wire.Thinking != "" || message.Role != "assistant" {
				return chatMessage{}, newError(providercontract.Unsupported, "reasoning_position", false)
			}
			raw, err := adapter.config.Reasoning.Resolve(ctx, item.ReferenceID, item.Digest)
			if err != nil {
				return chatMessage{}, newError(providercontract.Unavailable, "reasoning_resolution_failed", true)
			}
			canonical, err := canonicalJSON(raw)
			if err != nil || digest(thinkingDigestDomain, canonical) != item.Digest {
				return chatMessage{}, newError(providercontract.Denied, "reasoning_digest_mismatch", false)
			}
			var envelope thinkingEnvelope
			if err := decodeExact(canonical, &envelope); err != nil || !validText(envelope.Thinking, 1<<20) {
				return chatMessage{}, newError(providercontract.Denied, "reasoning_item_invalid", false)
			}
			wire.Thinking = envelope.Thinking
		case "tool_call":
			if message.Role != "assistant" {
				return chatMessage{}, newError(providercontract.Unsupported, "tool_call_position", false)
			}
			tool, exists := toolForCall(item, allowed, callTools)
			if !exists {
				return chatMessage{}, newError(providercontract.Denied, "tool_call_not_allowed", false)
			}
			canonical, err := canonicalJSON(item.Arguments)
			if err != nil || !jsonObject(canonical) {
				return chatMessage{}, newError(providercontract.InvalidInput, "tool_arguments_invalid", false)
			}
			callTools[item.CallID] = tool.Name
			index := uint64(len(wire.ToolCalls))
			wire.ToolCalls = append(wire.ToolCalls, nativeToolCall{Type: "function",
				Function: nativeFunctionCall{Index: &index, Name: tool.Name, Arguments: canonical}})
		case "tool_result":
			if message.Role != "tool" || len(message.Items) != 1 {
				return chatMessage{}, newError(providercontract.Unsupported, "tool_result_position", false)
			}
			toolName, exists := callTools[item.CallID]
			if !exists {
				return chatMessage{}, newError(providercontract.Denied, "tool_result_call_unknown", false)
			}
			canonical, err := canonicalJSON(item.Value)
			if err != nil {
				return chatMessage{}, err
			}
			envelope, err := json.Marshal(toolResultEnvelope{Outcome: item.Outcome, Value: canonical})
			if err != nil {
				return chatMessage{}, newError(providercontract.Internal, "tool_result_encoding", false)
			}
			wire.ToolName, wire.Content, contentCount = toolName, string(envelope), contentCount+1
		default:
			return chatMessage{}, newError(providercontract.Unsupported, "content_kind_not_supported", false)
		}
	}
	if strings.TrimSpace(wire.Content) == "" && wire.Thinking == "" && len(wire.ToolCalls) == 0 {
		return chatMessage{}, newError(providercontract.InvalidInput, "message_empty", false)
	}
	return wire, nil
}

func toolForCall(item providercontract.ContentItem, allowed map[string]providercontract.Tool,
	callTools map[string]string) (providercontract.Tool, bool) {
	name, already := callTools[item.CallID]
	if already && name != item.ToolName {
		return providercontract.Tool{}, false
	}
	tool, exists := allowed[item.ToolName]
	if exists && tool.InputSchemaDigest == item.InputSchemaDigest {
		return tool, true
	}
	return providercontract.Tool{}, false
}
