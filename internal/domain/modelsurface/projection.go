package modelsurface

import (
	"context"
	"encoding/json"
	"slices"
	"unicode/utf8"
)

type SurfacePayload struct {
	SchemaVersion   string          `json:"schema_version"`
	ContractVersion string          `json:"contract_version"`
	SurfaceKind     string          `json:"surface_kind"`
	Role            string          `json:"role"`
	Name            string          `json:"name"`
	MediaType       string          `json:"media_type"`
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
		!oneOf(value.MediaType, "application/json", "application/schema+json", "text/plain") ||
		len(value.Content) == 0 || len(value.Content) > MaximumInputBytes {
		return newError(InvalidInput, "payload")
	}
	var content any
	if err := json.Unmarshal(value.Content, &content); err != nil {
		return newError(InvalidInput, "payload_content")
	}
	switch value.MediaType {
	case "text/plain":
		text, ok := content.(string)
		if !ok || text == "" || len(text) > 8<<20 || !utf8.ValidString(text) {
			return newError(InvalidInput, "payload_content")
		}
	case "application/json", "application/schema+json":
		object, ok := content.(map[string]any)
		if !ok || len(object) > 4096 {
			return newError(InvalidInput, "payload_content")
		}
	}
	switch value.SurfaceKind {
	case "message":
		if !oneOf(value.Role, "system", "developer", "user", "assistant", "tool") || value.Name != "" {
			return newError(Denied, "payload_surface")
		}
	case "prompt_section":
		if !oneOf(value.Role, "system", "developer") || value.MediaType == "application/schema+json" {
			return newError(Denied, "payload_surface")
		}
	case "tool_schema":
		if !oneOf(value.Role, "system", "developer") || !validToken(value.Name) ||
			value.MediaType != "application/schema+json" {
			return newError(Denied, "payload_surface")
		}
	case "retrieved_context", "compaction_replacement":
		if value.Role != "data" {
			return newError(Denied, "payload_surface")
		}
	case "policy_notice":
		if !oneOf(value.Role, "system", "developer") {
			return newError(Denied, "payload_surface")
		}
	}
	return nil
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
	MediaType   string          `json:"media_type"`
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
		visibleItem := VisibleItem{Ordinal: uint64(index + 1), SurfaceKind: value.SurfaceKind, Role: value.Role,
			Name: value.Name, MediaType: value.MediaType, Content: append(json.RawMessage(nil), value.Content...)}
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

func projectionTrustAllowed(source Source, payload SurfacePayload) bool {
	if source.InstructionDisposition == "untrusted_data_only" {
		return !oneOf(payload.Role, "system", "developer") &&
			!oneOf(payload.SurfaceKind, "prompt_section", "tool_schema", "policy_notice")
	}
	return oneOf(payload.Role, "system", "developer") &&
		oneOf(payload.SurfaceKind, "message", "prompt_section", "tool_schema", "policy_notice")
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
