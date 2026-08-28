package modelsurface

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type SurfacePayload struct {
	SchemaVersion   string          `json:"schema_version"`
	ContractVersion string          `json:"contract_version"`
	SurfaceKind     string          `json:"surface_kind"`
	Role            string          `json:"role"`
	Name            string          `json:"name"`
	ContentKind     string          `json:"content_kind"`
	Content         json.RawMessage `json:"content"`
}

type ValidatedPayload struct{ canonical []byte }

func (value ValidatedPayload) CanonicalBytes() []byte { return append([]byte(nil), value.canonical...) }
func (value ValidatedPayload) Value() SurfacePayload {
	var result SurfacePayload
	_ = json.Unmarshal(value.canonical, &result)
	result.Content = append(json.RawMessage(nil), result.Content...)
	return result
}

func CanonicalPayload(value SurfacePayload) ([]byte, error) {
	if err := validatePayload(value); err != nil {
		return nil, err
	}
	return canonicalRecord(value)
}

func DecodePayload(ctx context.Context, input []byte) (ValidatedPayload, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedPayload{}, err
	}
	canonical, value, err := decodeCanonical[SurfacePayload](input)
	if err != nil {
		return ValidatedPayload{}, err
	}
	if err := validatePayload(value); err != nil {
		return ValidatedPayload{}, err
	}
	return ValidatedPayload{canonical: append([]byte(nil), canonical...)}, nil
}

func validatePayload(value SurfacePayload) error {
	if value.SchemaVersion != PayloadSchema || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "payload_contract")
	}
	if !validProjectionRule(value.SurfaceKind) ||
		!oneOf(value.Role, "system", "developer", "user", "assistant", "tool", "data") ||
		(value.Name != "" && !validToken(value.Name)) ||
		!oneOf(value.ContentKind, "text", "input_json", "output_json", "tool_call", "tool_result", "reasoning_ref", "tool_definition") ||
		len(value.Content) == 0 || len(value.Content) > MaximumInputBytes {
		return newError(InvalidInput, "payload")
	}
	if err := validatePayloadContent(value.ContentKind, value.Content); err != nil {
		return newError(InvalidInput, "payload_content")
	}
	switch value.SurfaceKind {
	case "message":
		if value.Name != "" || !messageContentAllowed(value.Role, value.ContentKind) {
			return newError(Denied, "payload_surface")
		}
	case "prompt_section":
		if !oneOf(value.Role, "system", "developer") || !oneOf(value.ContentKind, "text", "input_json") {
			return newError(Denied, "payload_surface")
		}
	case "tool_schema":
		if !oneOf(value.Role, "system", "developer") || !validToken(value.Name) ||
			value.ContentKind != "tool_definition" {
			return newError(Denied, "payload_surface")
		}
	case "retrieved_context", "compaction_replacement":
		if value.Role != "data" || !oneOf(value.ContentKind, "text", "input_json") {
			return newError(Denied, "payload_surface")
		}
	case "policy_notice":
		if !oneOf(value.Role, "system", "developer") || !oneOf(value.ContentKind, "text", "input_json") {
			return newError(Denied, "payload_surface")
		}
	}
	return nil
}

type payloadJSONContent struct {
	Value        json.RawMessage `json:"value"`
	SchemaDigest string          `json:"schema_digest"`
}
type payloadToolCall struct {
	CallID            string          `json:"call_id"`
	ToolName          string          `json:"tool_name"`
	Arguments         json.RawMessage `json:"arguments"`
	InputSchemaDigest string          `json:"input_schema_digest"`
}
type payloadToolResult struct {
	CallID             string          `json:"call_id"`
	Outcome            string          `json:"outcome"`
	Value              json.RawMessage `json:"value"`
	OutputSchemaDigest string          `json:"output_schema_digest"`
	ResultDigest       string          `json:"result_digest"`
}
type payloadReasoningRef struct {
	ReferenceID string `json:"reference_id"`
	Digest      string `json:"digest"`
}
type payloadToolDefinition struct {
	Description        string `json:"description"`
	InputSchemaDigest  string `json:"input_schema_digest"`
	OutputSchemaDigest string `json:"output_schema_digest"`
}

func validatePayloadContent(kind string, raw json.RawMessage) error {
	switch kind {
	case "text":
		var text string
		if err := json.Unmarshal(raw, &text); err != nil || text == "" || len(text) > 8<<20 || !utf8.ValidString(text) {
			return newError(InvalidInput, "payload_text")
		}
	case "input_json", "output_json":
		var value payloadJSONContent
		if decodePayloadContent(raw, &value) != nil || !validJSONObject(value.Value) || !validDigest(value.SchemaDigest) {
			return newError(InvalidInput, "payload_json")
		}
	case "tool_call":
		var value payloadToolCall
		if decodePayloadContent(raw, &value) != nil || len(value.CallID) == 0 || len(value.CallID) > 128 ||
			!validToken(value.ToolName) || !validJSONObject(value.Arguments) || !validDigest(value.InputSchemaDigest) {
			return newError(InvalidInput, "payload_tool_call")
		}
	case "tool_result":
		var value payloadToolResult
		if decodePayloadContent(raw, &value) != nil {
			return newError(InvalidInput, "payload_tool_result")
		}
		digest, digestErr := providercontract.DigestToolResult(value.Value)
		if len(value.CallID) == 0 || len(value.CallID) > 128 ||
			!oneOf(value.Outcome, "succeeded", "denied", "canceled", "timeout", "failed", "uncertain") ||
			!validJSONObject(value.Value) || !validDigest(value.OutputSchemaDigest) || digestErr != nil || digest != value.ResultDigest {
			return newError(InvalidInput, "payload_tool_result")
		}
	case "reasoning_ref":
		var value payloadReasoningRef
		if decodePayloadContent(raw, &value) != nil || len(value.ReferenceID) == 0 || len(value.ReferenceID) > 256 || !validDigest(value.Digest) {
			return newError(InvalidInput, "payload_reasoning")
		}
	case "tool_definition":
		var value payloadToolDefinition
		if decodePayloadContent(raw, &value) != nil || len(value.Description) == 0 || len(value.Description) > 4096 ||
			!validDigest(value.InputSchemaDigest) || !validDigest(value.OutputSchemaDigest) {
			return newError(InvalidInput, "payload_tool_definition")
		}
	default:
		return newError(Unsupported, "payload_content_kind")
	}
	return nil
}

func decodePayloadContent(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(InvalidInput, "payload_content_shape")
	}
	reencoded, err := canonicalRecord(target)
	if err != nil || !bytes.Equal(reencoded, input) {
		return newError(InvalidInput, "payload_content_shape")
	}
	return nil
}

func validJSONObject(value json.RawMessage) bool {
	var object map[string]any
	return len(value) > 0 && json.Unmarshal(value, &object) == nil && object != nil
}

func messageContentAllowed(role, kind string) bool {
	switch role {
	case "system", "developer", "user":
		return oneOf(kind, "text", "input_json")
	case "assistant":
		return oneOf(kind, "text", "output_json", "tool_call", "reasoning_ref")
	case "tool":
		return kind == "tool_result"
	default:
		return false
	}
}

type ProjectionRequest struct {
	ProjectionID      string
	Scope             Scope
	RunID             string
	VocabularyDigest  string
	CompositionDigest string
	Sources           []SourceReference
	CreatedAt         string
}

type VisibleItem struct {
	Ordinal     uint64          `json:"ordinal"`
	SurfaceKind string          `json:"surface_kind"`
	Role        string          `json:"role"`
	Name        string          `json:"name"`
	ContentKind string          `json:"content_kind"`
	Content     json.RawMessage `json:"content"`
}

type ProjectedSurface struct {
	projection      Projection
	projectionBytes []byte
	items           []VisibleItem
}

func (value ProjectedSurface) Projection() Projection { return cloneProjection(value.projection) }
func (value ProjectedSurface) ProjectionBytes() []byte {
	return append([]byte(nil), value.projectionBytes...)
}
func (value ProjectedSurface) Items() []VisibleItem { return cloneVisibleItems(value.items) }

type Projector struct{ resolver *Resolver }

func NewProjector(resolver *Resolver) (*Projector, error) {
	if resolver == nil {
		return nil, newError(InvalidInput, "projector_dependencies")
	}
	return &Projector{resolver: resolver}, nil
}

func (projector *Projector) Project(ctx context.Context, request ProjectionRequest) (ProjectedSurface, error) {
	if projector == nil || projector.resolver == nil {
		return ProjectedSurface{}, newError(InvalidInput, "projector_dependencies")
	}
	if err := contextError(ctx); err != nil {
		return ProjectedSurface{}, err
	}
	if !validUUID7(request.ProjectionID) || !validScope(request.Scope) || !validUUID7(request.RunID) ||
		!validDigest(request.VocabularyDigest) || !validDigest(request.CompositionDigest) ||
		len(request.Sources) == 0 || len(request.Sources) > MaximumItems || !validTimestamp(request.CreatedAt) {
		return ProjectedSurface{}, newError(InvalidInput, "projection_request")
	}
	resolved, err := projector.resolver.Resolve(ctx, ResolveRequest{Scope: request.Scope, RunID: request.RunID,
		VocabularyDigest: request.VocabularyDigest, Sources: append([]SourceReference(nil), request.Sources...)})
	if err != nil {
		return ProjectedSurface{}, err
	}
	resolvedItems := resolved.Items()
	visible := make([]VisibleItem, 0, len(resolvedItems))
	projected := make([]ProjectedItem, 0, len(resolvedItems))
	sourceIDs := make([]string, 0, len(resolvedItems))
	artifacts := make([]string, 0, len(resolvedItems))
	totalBytes := uint64(0)
	var previousSequence uint64
	for index, item := range resolvedItems {
		if err := contextError(ctx); err != nil {
			return ProjectedSurface{}, err
		}
		source := item.Source()
		if index > 0 && source.Sequence <= previousSequence {
			return ProjectedSurface{}, newError(Denied, "projection_order")
		}
		previousSequence = source.Sequence
		payload, decodeErr := DecodePayload(ctx, item.ContentBytes())
		if decodeErr != nil {
			return ProjectedSurface{}, newError(Denied, "projection_payload")
		}
		value := payload.Value()
		if value.SurfaceKind != source.ProjectionRule || !projectionTrustAllowed(source, value) {
			return ProjectedSurface{}, newError(Denied, "projection_trust")
		}
		visibleRole := value.Role
		if visibleRole == "data" {
			visibleRole = "user"
		}
		visibleItem := VisibleItem{Ordinal: uint64(index + 1), SurfaceKind: value.SurfaceKind, Role: visibleRole,
			Name: value.Name, ContentKind: value.ContentKind, Content: append(json.RawMessage(nil), value.Content...)}
		rendered, encodeErr := canonicalRecord(visibleItem)
		if encodeErr != nil {
			return ProjectedSurface{}, encodeErr
		}
		totalBytes += uint64(len(rendered))
		if totalBytes > MaximumSurfaceBytes {
			return ProjectedSurface{}, newError(Denied, "surface_size")
		}
		visible = append(visible, visibleItem)
		projected = append(projected, ProjectedItem{Ordinal: visibleItem.Ordinal, SurfaceKind: visibleItem.SurfaceKind,
			Role: visibleItem.Role, SourceRecordID: source.SourceRecordID, SourceRevision: source.RecordRevision,
			SourceDigest: source.SourceDigest, ContentKind: source.Content.Kind, ContentID: source.Content.ContentID,
			ContentDigest: source.Content.Digest, RenderedDigest: rawDigest(rendered), RenderedLength: uint64(len(rendered)),
			InstructionDisposition: source.InstructionDisposition})
		sourceIDs = append(sourceIDs, source.SourceRecordID)
		if source.Content.Kind == "immutable_artifact" {
			artifacts = append(artifacts, source.Content.Digest)
		}
	}
	slices.Sort(artifacts)
	artifacts = slices.Compact(artifacts)
	surfaceDigest, err := canonicalDigest(ctx, surfaceDigestDomain, visible)
	if err != nil {
		return ProjectedSurface{}, err
	}
	projection := Projection{SchemaVersion: ProjectionSchema, ContractVersion: ContractVersion,
		ProjectionID: request.ProjectionID, ProjectionVersion: ProjectionVersion, Scope: request.Scope, RunID: request.RunID,
		VocabularyDigest: request.VocabularyDigest, CompositionDigest: request.CompositionDigest, OrderedItems: projected,
		OrderedSourceRecordIDs: sourceIDs, ArtifactDigests: artifacts, SurfaceDigest: surfaceDigest, CreatedAt: request.CreatedAt}
	projectionBytes, _, err := CanonicalProjection(ctx, projection)
	if err != nil {
		return ProjectedSurface{}, err
	}
	validated, err := DecodeProjection(ctx, projectionBytes)
	if err != nil {
		return ProjectedSurface{}, err
	}
	return ProjectedSurface{projection: validated.Value(), projectionBytes: validated.CanonicalBytes(), items: cloneVisibleItems(visible)}, nil
}

// Reproject re-resolves every immutable input named by a durable projection
// and requires byte-identical projection and surface digests.
func (projector *Projector) Reproject(ctx context.Context, expected Projection) (ProjectedSurface, error) {
	references := make([]SourceReference, len(expected.OrderedItems))
	for index, item := range expected.OrderedItems {
		references[index] = SourceReference{SourceRecordID: item.SourceRecordID, RecordRevision: item.SourceRevision, SourceDigest: item.SourceDigest}
	}
	actual, err := projector.Project(ctx, ProjectionRequest{ProjectionID: expected.ProjectionID, Scope: expected.Scope,
		RunID: expected.RunID, VocabularyDigest: expected.VocabularyDigest, CompositionDigest: expected.CompositionDigest,
		Sources: references, CreatedAt: expected.CreatedAt})
	if err != nil {
		return ProjectedSurface{}, err
	}
	if actual.Projection().ProjectionDigest != expected.ProjectionDigest || actual.Projection().SurfaceDigest != expected.SurfaceDigest {
		return ProjectedSurface{}, newError(Denied, "reprojection_drift")
	}
	return actual, nil
}

func projectionTrustAllowed(source Source, payload SurfacePayload) bool {
	switch source.InstructionDisposition {
	case "untrusted_data_only":
		return !oneOf(payload.Role, "system", "developer") &&
			!oneOf(payload.SurfaceKind, "prompt_section", "tool_schema", "policy_notice")
	case "trusted_user_instruction":
		return payload.Role == "user" && payload.SurfaceKind == "message"
	case "trusted_control_instruction", "trusted_system_instruction":
		return oneOf(payload.Role, "system", "developer") &&
			oneOf(payload.SurfaceKind, "message", "prompt_section", "tool_schema", "policy_notice")
	default:
		return false
	}
}

func cloneProjection(value Projection) Projection {
	value.OrderedItems = append([]ProjectedItem(nil), value.OrderedItems...)
	value.OrderedSourceRecordIDs = append([]string(nil), value.OrderedSourceRecordIDs...)
	value.ArtifactDigests = append([]string(nil), value.ArtifactDigests...)
	return value
}
func cloneVisibleItems(values []VisibleItem) []VisibleItem {
	result := make([]VisibleItem, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Content = append(json.RawMessage(nil), value.Content...)
	}
	return result
}
