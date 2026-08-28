package modelsurface

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

// AdmittedInference is the only model-surface-owned proof that a provider
// request was assembled from an exact, sealed projection.
type AdmittedInference struct {
	request providercontract.ValidatedRequest
	binding InferenceBinding
}

func (value AdmittedInference) Request() providercontract.ValidatedRequest { return value.request }
func (value AdmittedInference) Binding() InferenceBinding                  { return cloneBinding(value.binding) }

// AdmitInference constructs all provider-visible messages and tools from the
// projection. Callers may supply dispatch controls, but no visible content.
func AdmitInference(ctx context.Context, surface ProjectedSurface, template providercontract.InferenceRequest) (AdmittedInference, error) {
	if err := contextError(ctx); err != nil {
		return AdmittedInference{}, err
	}
	if len(template.Messages) != 0 || len(template.Tools) != 0 || !emptyProviderSurface(template.ModelSurface) {
		return AdmittedInference{}, newError(Denied, "caller_visible_surface")
	}
	projection, items, err := validateProjectedSurface(ctx, surface)
	if err != nil {
		return AdmittedInference{}, err
	}
	if template.OrganizationID != projection.Scope.OrganizationID || template.TenantID != projection.Scope.TenantID ||
		template.CaseID != projection.Scope.CaseID || template.TaskID != projection.Scope.TaskID {
		return AdmittedInference{}, newError(Denied, "dispatch_scope")
	}
	providerID := template.Provider.ProviderKind + "." + template.Provider.DataRoute
	binding, err := SealBinding(ctx, InferenceBinding{SchemaVersion: BindingSchema, ContractVersion: ContractVersion,
		RequestID: template.RequestID, AttemptID: template.AttemptID, Scope: projection.Scope, RunID: projection.RunID,
		ActorID: template.ActorID, ProviderID: providerID, ProjectionID: projection.ProjectionID,
		ProjectionVersion: projection.ProjectionVersion, ProjectionDigest: projection.ProjectionDigest,
		OrderedSourceRecordIDs: append([]string(nil), projection.OrderedSourceRecordIDs...),
		ArtifactDigests:        append([]string(nil), projection.ArtifactDigests...), VocabularyDigest: projection.VocabularyDigest,
		CompositionDigest: projection.CompositionDigest, SurfaceDigest: projection.SurfaceDigest,
		AuthorizationDigest: template.AuthorizationDigest, PolicyDecisionDigest: template.PolicyDecisionDigest,
		ApprovalDecisionDigest: template.ApprovalDecisionDigest, AuditReservationDigest: template.AuditReservationDigest,
		CreatedAt: projection.CreatedAt, Deadline: template.Deadline})
	if err != nil {
		return AdmittedInference{}, err
	}
	messages := make([]providercontract.Message, 0, len(items))
	tools := make([]providercontract.Tool, 0)
	for index, item := range items {
		if item.ContentKind == "tool_definition" {
			var definition payloadToolDefinition
			if decodePayloadContent(item.Content, &definition) != nil {
				return AdmittedInference{}, newError(Denied, "dispatch_content")
			}
			tools = append(tools, providercontract.Tool{Name: item.Name, Description: definition.Description,
				InputSchemaDigest: definition.InputSchemaDigest, OutputSchemaDigest: definition.OutputSchemaDigest})
			continue
		}
		content, convertErr := providerContent(item)
		if convertErr != nil {
			return AdmittedInference{}, convertErr
		}
		messages = append(messages, providercontract.Message{MessageID: projection.OrderedSourceRecordIDs[index], Role: item.Role,
			Items: []providercontract.ContentItem{content}})
	}
	slices.SortFunc(tools, func(left, right providercontract.Tool) int {
		if left.Name < right.Name {
			return -1
		}
		if left.Name > right.Name {
			return 1
		}
		return 0
	})
	template.Messages = messages
	template.Tools = tools
	template.ModelSurface = providercontract.ModelSurfaceBinding{RunID: binding.RunID, ProviderID: binding.ProviderID,
		ProjectionID: binding.ProjectionID, ProjectionVersion: binding.ProjectionVersion, ProjectionDigest: binding.ProjectionDigest,
		OrderedSourceRecordIDs: append([]string(nil), binding.OrderedSourceRecordIDs...), ArtifactDigests: append([]string(nil), binding.ArtifactDigests...),
		VocabularyDigest: binding.VocabularyDigest, CompositionDigest: binding.CompositionDigest, SurfaceDigest: binding.SurfaceDigest,
		BindingDigest: binding.BindingDigest}
	encoded, err := json.Marshal(template)
	if err != nil {
		return AdmittedInference{}, newError(InvalidInput, "dispatch_encoding")
	}
	validated, err := providercontract.DecodeRequest(ctx, encoded)
	if err != nil {
		return AdmittedInference{}, newError(Denied, "provider_request")
	}
	return AdmittedInference{request: validated, binding: cloneBinding(binding)}, nil
}

func validateProjectedSurface(ctx context.Context, surface ProjectedSurface) (Projection, []VisibleItem, error) {
	if len(surface.projectionBytes) == 0 || len(surface.items) == 0 {
		return Projection{}, nil, newError(InvalidInput, "projected_surface")
	}
	validated, err := DecodeProjection(ctx, surface.projectionBytes)
	if err != nil {
		return Projection{}, nil, newError(Denied, "projection_seal")
	}
	projection := validated.Value()
	items := surface.Items()
	if len(items) != len(projection.OrderedItems) {
		return Projection{}, nil, newError(Denied, "projection_items")
	}
	for index, item := range items {
		rendered, encodeErr := canonicalRecord(item)
		projected := projection.OrderedItems[index]
		if encodeErr != nil || item.Ordinal != uint64(index+1) || item.SurfaceKind != projected.SurfaceKind ||
			item.Role != projected.Role || rawDigest(rendered) != projected.RenderedDigest || uint64(len(rendered)) != projected.RenderedLength {
			return Projection{}, nil, newError(Denied, "projection_items")
		}
	}
	digest, err := canonicalDigest(ctx, surfaceDigestDomain, items)
	if err != nil || digest != projection.SurfaceDigest {
		return Projection{}, nil, newError(Denied, "surface_digest")
	}
	return projection, items, nil
}

func providerContent(item VisibleItem) (providercontract.ContentItem, error) {
	result := providercontract.ContentItem{Kind: item.ContentKind}
	switch item.ContentKind {
	case "text":
		if json.Unmarshal(item.Content, &result.Text) != nil {
			return providercontract.ContentItem{}, newError(Denied, "dispatch_content")
		}
	case "input_json", "output_json":
		var value payloadJSONContent
		if decodePayloadContent(item.Content, &value) != nil {
			return providercontract.ContentItem{}, newError(Denied, "dispatch_content")
		}
		result.Value, result.SchemaDigest = append(json.RawMessage(nil), value.Value...), value.SchemaDigest
	case "tool_call":
		var value payloadToolCall
		if decodePayloadContent(item.Content, &value) != nil {
			return providercontract.ContentItem{}, newError(Denied, "dispatch_content")
		}
		result.CallID, result.ToolName, result.Arguments, result.InputSchemaDigest = value.CallID, value.ToolName, append(json.RawMessage(nil), value.Arguments...), value.InputSchemaDigest
	case "tool_result":
		var value payloadToolResult
		if decodePayloadContent(item.Content, &value) != nil {
			return providercontract.ContentItem{}, newError(Denied, "dispatch_content")
		}
		result.CallID, result.Outcome, result.Value = value.CallID, value.Outcome, append(json.RawMessage(nil), value.Value...)
		result.OutputSchemaDigest, result.ResultDigest = value.OutputSchemaDigest, value.ResultDigest
	case "reasoning_ref":
		var value payloadReasoningRef
		if decodePayloadContent(item.Content, &value) != nil {
			return providercontract.ContentItem{}, newError(Denied, "dispatch_content")
		}
		result.ReferenceID, result.Digest = value.ReferenceID, value.Digest
	default:
		return providercontract.ContentItem{}, newError(Unsupported, "dispatch_content_kind")
	}
	return result, nil
}

func emptyProviderSurface(value providercontract.ModelSurfaceBinding) bool {
	return value.RunID == "" && value.ProviderID == "" && value.ProjectionID == "" && value.ProjectionVersion == "" &&
		value.ProjectionDigest == "" && len(value.OrderedSourceRecordIDs) == 0 && len(value.ArtifactDigests) == 0 &&
		value.VocabularyDigest == "" && value.CompositionDigest == "" && value.SurfaceDigest == "" && value.BindingDigest == ""
}

func cloneBinding(value InferenceBinding) InferenceBinding {
	value.OrderedSourceRecordIDs = append([]string(nil), value.OrderedSourceRecordIDs...)
	value.ArtifactDigests = append([]string(nil), value.ArtifactDigests...)
	return value
}
