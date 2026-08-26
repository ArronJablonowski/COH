package ollama

import (
	"context"
	"encoding/json"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func (adapter *Adapter) resolveSchema(ctx context.Context, schemaDigest string) (json.RawMessage, error) {
	document, err := adapter.config.Schemas.Resolve(ctx, schemaDigest)
	if err != nil {
		return nil, newError(providercontract.Unavailable, "schema_resolution_failed", true)
	}
	if document.Digest != schemaDigest || len(document.JSON) == 0 || len(document.JSON) > providercontract.MaximumInputBytes {
		return nil, newError(providercontract.Denied, "schema_digest_mismatch", false)
	}
	canonical, err := canonicalJSON(document.JSON)
	if err != nil {
		return nil, err
	}
	var schema struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(canonical, &schema); err != nil || schema.Type != "object" || schema.Properties == nil ||
		schema.AdditionalProperties == nil || *schema.AdditionalProperties || len(schema.Required) != len(schema.Properties) {
		return nil, newError(providercontract.Unsupported, "schema_not_strict", false)
	}
	required := make(map[string]struct{}, len(schema.Required))
	for _, name := range schema.Required {
		if _, exists := schema.Properties[name]; !exists {
			return nil, newError(providercontract.InvalidInput, "schema_required_property", false)
		}
		required[name] = struct{}{}
	}
	if len(required) != len(schema.Required) {
		return nil, newError(providercontract.InvalidInput, "schema_required_duplicate", false)
	}
	return append(json.RawMessage(nil), canonical...), nil
}
