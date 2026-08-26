package openairesponses

import (
	"context"
	"encoding/json"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type requestTranslation struct {
	wire  createRequest
	tools map[string]providercontract.Tool
}

func (adapter *Adapter) translateRequest(ctx context.Context, request providercontract.InferenceRequest) (requestTranslation, error) {
	if request.Sampling.Seed != 0 || request.State.Mode != "stateless" {
		return requestTranslation{}, newError(providercontract.Unsupported, "request_feature_not_supported", false)
	}
	translation := requestTranslation{tools: make(map[string]providercontract.Tool, len(request.Tools))}
	translation.wire = createRequest{Model: request.Provider.RequestedModel,
		ParallelToolCalls: false, Temperature: float64(request.Sampling.TemperatureMilli) / 1000,
		TopP: float64(request.Sampling.TopPMillionths) / 1000000, MaxOutputTokens: request.MaximumOutputTokens,
		Include: []string{"reasoning.encrypted_content"}, Store: false, Background: false,
		Truncation: "disabled", Stream: false}
	for _, tool := range request.Tools {
		inputSchema, err := adapter.resolveSchema(ctx, tool.InputSchemaDigest)
		if err != nil {
			return requestTranslation{}, err
		}
		if _, err := adapter.resolveSchema(ctx, tool.OutputSchemaDigest); err != nil {
			return requestTranslation{}, err
		}
		translation.tools[tool.Name] = tool
		translation.wire.Tools = append(translation.wire.Tools, functionTool{Type: "function", Name: tool.Name,
			Description: tool.Description, Parameters: inputSchema, Strict: true})
	}
	if len(translation.wire.Tools) > 0 {
		translation.wire.ToolChoice = "auto"
	}
	if request.OutputConstraint.Kind == "json_schema" {
		schema, err := adapter.resolveSchema(ctx, request.OutputConstraint.SchemaDigest)
		if err != nil {
			return requestTranslation{}, err
		}
		translation.wire.Text = &textConfig{Format: jsonSchemaFormat{Type: "json_schema", Name: request.OutputConstraint.Name,
			Schema: schema, Strict: true}}
	}
	for _, message := range request.Messages {
		items, err := adapter.translateMessage(ctx, message)
		if err != nil {
			return requestTranslation{}, err
		}
		translation.wire.Input = append(translation.wire.Input, items...)
	}
	return translation, nil
}

func (adapter *Adapter) translateMessage(ctx context.Context, message providercontract.Message) ([]json.RawMessage, error) {
	items := make([]json.RawMessage, 0, len(message.Items))
	for _, item := range message.Items {
		var wire any
		switch item.Kind {
		case "text":
			kind := "input_text"
			if message.Role == "assistant" {
				kind = "output_text"
			}
			wire = inputMessage{Type: "message", Role: message.Role, Content: []inputContent{{Type: kind, Text: item.Text}}}
		case "input_json", "output_json":
			kind := "input_text"
			if message.Role == "assistant" {
				kind = "output_text"
			}
			canonical, err := canonicalJSON(item.Value)
			if err != nil {
				return nil, err
			}
			wire = inputMessage{Type: "message", Role: message.Role, Content: []inputContent{{Type: kind, Text: string(canonical)}}}
		case "tool_call":
			canonical, err := canonicalJSON(item.Arguments)
			if err != nil {
				return nil, err
			}
			wire = inputFunctionCall{Type: "function_call", CallID: item.CallID, Name: item.ToolName, Arguments: string(canonical)}
		case "tool_result":
			canonical, err := canonicalJSON(item.Value)
			if err != nil {
				return nil, err
			}
			envelope, err := json.Marshal(functionOutputEnvelope{Outcome: item.Outcome, Value: canonical})
			if err != nil {
				return nil, newError(providercontract.Internal, "tool_result_encoding", false)
			}
			wire = inputFunctionOutput{Type: "function_call_output", CallID: item.CallID, Output: string(envelope)}
		case "reasoning_ref":
			raw, err := adapter.config.Reasoning.Resolve(ctx, item.ReferenceID, item.Digest)
			if err != nil {
				return nil, newError(providercontract.Unavailable, "reasoning_resolution_failed", true)
			}
			canonical, err := canonicalJSON(raw)
			if err != nil || digestReasoning(canonical) != item.Digest {
				return nil, newError(providercontract.Denied, "reasoning_digest_mismatch", false)
			}
			var reasoning reasoningItem
			if err := decodeExact(canonical, &reasoning); err != nil || validateReasoning(reasoning) != nil {
				return nil, newError(providercontract.Denied, "reasoning_item_invalid", false)
			}
			items = append(items, canonical)
			continue
		default:
			return nil, newError(providercontract.Unsupported, "content_kind_not_supported", false)
		}
		encoded, err := json.Marshal(wire)
		if err != nil {
			return nil, newError(providercontract.Internal, "request_encoding", false)
		}
		items = append(items, encoded)
	}
	return items, nil
}
