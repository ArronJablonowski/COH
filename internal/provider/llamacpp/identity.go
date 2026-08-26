package llamacpp

import (
	"context"
	"encoding/json"
	"math"
	"regexp"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	templateDigestDomain = "COH-LLAMACPP-TEMPLATE-V1\x00"
	modelMetaDomain      = "COH-LLAMACPP-MODEL-META-V1\x00"
)

type observedIdentity struct {
	BuildInfo       string
	RuntimeVersion  string
	ModelAlias      string
	ModelPath       string
	TemplateDigest  string
	ModelMetaDigest string
	ContextLimit    uint64
}

func (adapter *Adapter) observeIdentity(ctx context.Context, model string) (observedIdentity, error) {
	var health healthResponse
	if _, err := adapter.getJSON(ctx, HealthPath, &health); err != nil {
		return observedIdentity{}, err
	}
	if health.Status != "ok" {
		return observedIdentity{}, newError(providercontract.Unavailable, "runtime_not_ready", true)
	}
	var properties propertiesResponse
	if _, err := adapter.getJSON(ctx, PropertiesPath, &properties); err != nil {
		return observedIdentity{}, err
	}
	contextLimit, err := validateProperties(properties)
	if err != nil {
		return observedIdentity{}, err
	}
	runtimeVersion, err := normalizeBuildInfo(properties.BuildInfo)
	if err != nil {
		return observedIdentity{}, err
	}
	var models modelsResponse
	if _, err := adapter.getJSON(ctx, ModelsPath, &models); err != nil {
		return observedIdentity{}, err
	}
	metadataDigest, err := validateModels(models, model, contextLimit)
	if err != nil {
		return observedIdentity{}, err
	}
	return observedIdentity{BuildInfo: properties.BuildInfo, RuntimeVersion: runtimeVersion,
		ModelAlias: model, ModelPath: properties.ModelPath,
		TemplateDigest:  digest(templateDigestDomain, []byte(properties.ChatTemplate)),
		ModelMetaDigest: metadataDigest, ContextLimit: contextLimit}, nil
}

func validateProperties(value propertiesResponse) (uint64, error) {
	if value.TotalSlots == 0 || !validText(value.ModelPath, 4096) || value.ChatTemplate == "" ||
		len(value.ChatTemplate) > 1<<20 || !validText(value.BuildInfo, 128) || value.IsSleeping ||
		value.Modalities.Vision || value.MediaMarker != "" && !validText(value.MediaMarker, 256) ||
		!requiredTemplateCaps(value.ChatTemplateCaps) {
		return 0, newError(providercontract.Denied, "runtime_properties_invalid", false)
	}
	var defaults map[string]json.RawMessage
	if err := json.Unmarshal(value.DefaultGenerationSettings, &defaults); err != nil {
		return 0, newError(providercontract.InvalidInput, "generation_defaults_invalid", false)
	}
	var contextLimit uint64
	if err := json.Unmarshal(defaults["n_ctx"], &contextLimit); err != nil || contextLimit == 0 {
		return 0, newError(providercontract.InvalidInput, "runtime_context_invalid", false)
	}
	return contextLimit, nil
}

func requiredTemplateCaps(value chatTemplateCaps) bool {
	return value.SupportsStringContent && value.SupportsTools && value.SupportsToolCalls &&
		value.SupportsParallelToolCalls && value.SupportsSystemRole && value.SupportsPreserveReasoning
}

func validateModels(value modelsResponse, model string, contextLimit uint64) (string, error) {
	if value.Object != "list" || len(value.Data) != 1 {
		return "", newError(providercontract.Denied, "model_identity_ambiguous", false)
	}
	record := value.Data[0]
	meta := record.Meta
	if record.ID != model || record.Object != "model" || record.OwnedBy != "llamacpp" || record.Created <= 0 ||
		meta.VocabularySize == 0 || meta.TrainingContext < contextLimit || meta.EmbeddingSize == 0 ||
		meta.ParameterCount == 0 || meta.SizeBytes == 0 || meta.ParameterCount > math.MaxInt64 {
		return "", newError(providercontract.Denied, "model_metadata_invalid", false)
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return "", newError(providercontract.Internal, "model_metadata_encoding", false)
	}
	canonical, err := canonicalJSON(encoded)
	if err != nil {
		return "", err
	}
	return digest(modelMetaDomain, canonical), nil
}

func (adapter *Adapter) verifyIdentity(ctx context.Context, requested string) error {
	observed, err := adapter.observeIdentity(ctx, requested)
	if err != nil {
		return err
	}
	provider := adapter.config.Capability.Value().Provider
	if observed.RuntimeVersion != provider.RuntimeVersion ||
		observed.ModelAlias != provider.ActualModel || observed.TemplateDigest != provider.ChatTemplateDigest ||
		observed.ModelMetaDigest != provider.TokenizerDigest || observed.ContextLimit != provider.ContextLimit {
		return newError(providercontract.Denied, "observed_identity_drift", false)
	}
	observation := LocalRouteObservation{Endpoint: adapter.config.Endpoint, BuildInfo: observed.BuildInfo,
		ExpectedRuntimeDigest: provider.RuntimeDigest, ModelAlias: observed.ModelAlias, ModelPath: observed.ModelPath,
		ExpectedGGUFDigest: provider.ModelRevision, ChatTemplateDigest: observed.TemplateDigest}
	if err := adapter.config.Route.VerifyLocal(ctx, observation); err != nil {
		return newError(providercontract.Denied, "local_route_attestation_failed", false)
	}
	return nil
}

var buildInfoPattern = regexp.MustCompile(`^b([0-9]+)-([A-Fa-f0-9]{7,64})$`)

func normalizeBuildInfo(value string) (string, error) {
	match := buildInfoPattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return "", newError(providercontract.InvalidInput, "runtime_build_info_invalid", false)
	}
	return match[1] + ".0+" + match[2], nil
}
