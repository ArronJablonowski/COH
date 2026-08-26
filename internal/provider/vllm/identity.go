package vllm

import (
	"context"
	"encoding/json"
	"regexp"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	templateDigestDomain  = "COH-VLLM-TEMPLATE-V1\x00"
	tokenizerDigestDomain = "COH-VLLM-TOKENIZER-V1\x00"
)

type observedIdentity struct {
	RuntimeVersion   string
	ModelAlias       string
	ModelRoot        string
	TokenizerName    string
	TokenizerVersion string
	TokenizerDigest  string
	TemplateDigest   string
	ContextLimit     uint64
}

func (adapter *Adapter) observeIdentity(ctx context.Context, model string) (observedIdentity, error) {
	if err := adapter.checkHealth(ctx); err != nil {
		return observedIdentity{}, err
	}
	var version versionResponse
	if _, err := adapter.getJSON(ctx, VersionPath, &version); err != nil {
		return observedIdentity{}, err
	}
	if !versionPattern.MatchString(version.Version) {
		return observedIdentity{}, newError(providercontract.Denied, "runtime_version_invalid", false)
	}
	var models modelsResponse
	if _, err := adapter.getJSON(ctx, ModelsPath, &models); err != nil {
		return observedIdentity{}, err
	}
	root, contextLimit, err := validateModels(models, model)
	if err != nil {
		return observedIdentity{}, err
	}
	var info tokenizerInfo
	canonical, err := adapter.getJSON(ctx, TokenizerInfoPath, &info)
	if err != nil {
		return observedIdentity{}, err
	}
	name, tokenizerVersion, template, err := validateTokenizerInfo(info, contextLimit)
	if err != nil {
		return observedIdentity{}, err
	}
	return observedIdentity{RuntimeVersion: version.Version, ModelAlias: model, ModelRoot: root,
		TokenizerName: name, TokenizerVersion: tokenizerVersion,
		TokenizerDigest: digest(tokenizerDigestDomain, canonical), TemplateDigest: digest(templateDigestDomain, []byte(template)),
		ContextLimit: contextLimit}, nil
}

func validateModels(value modelsResponse, model string) (string, uint64, error) {
	if value.Object != "list" || len(value.Data) != 1 {
		return "", 0, newError(providercontract.Denied, "model_identity_ambiguous", false)
	}
	record := value.Data[0]
	if record.ID != model || record.Object != "model" || record.OwnedBy != "vllm" || record.Created <= 0 ||
		record.Root == nil || !validText(*record.Root, 4096) || record.Parent != nil || record.MaximumModelLength == nil || *record.MaximumModelLength == 0 || len(record.Permission) != 1 {
		return "", 0, newError(providercontract.Denied, "model_metadata_invalid", false)
	}
	permission := record.Permission[0]
	if !validText(permission.ID, 128) || permission.Object != "model_permission" || permission.Created <= 0 ||
		permission.AllowCreateEngine || !permission.AllowSampling || !permission.AllowLogprobs || permission.AllowSearchIndices ||
		!permission.AllowView || permission.AllowFineTuning || permission.Organization != "*" || permission.Group != nil || permission.IsBlocking {
		return "", 0, newError(providercontract.Denied, "model_permission_invalid", false)
	}
	return *record.Root, *record.MaximumModelLength, nil
}

func validateTokenizerInfo(value tokenizerInfo, contextLimit uint64) (string, string, string, error) {
	name, ok := rawString(value["tokenizer_class"])
	if !ok || !validText(name, 256) {
		return "", "", "", newError(providercontract.Denied, "tokenizer_identity_invalid", false)
	}
	template, ok := rawString(value["chat_template"])
	if !ok || template == "" || len(template) > 1<<20 {
		return "", "", "", newError(providercontract.Denied, "chat_template_invalid", false)
	}
	modelLength, ok := rawUint(value["model_max_length"])
	if !ok || modelLength < contextLimit {
		return "", "", "", newError(providercontract.Denied, "tokenizer_context_invalid", false)
	}
	version, ok := rawString(value["tokenizer_version"])
	if !ok || !validText(version, 128) {
		return "", "", "", newError(providercontract.Denied, "tokenizer_version_invalid", false)
	}
	return name, version, template, nil
}

func rawString(raw json.RawMessage) (string, bool) {
	var value string
	err := json.Unmarshal(raw, &value)
	return value, err == nil
}
func rawUint(raw json.RawMessage) (uint64, bool) {
	var value uint64
	err := json.Unmarshal(raw, &value)
	return value, err == nil
}

func (adapter *Adapter) verifyIdentity(ctx context.Context, requested string) error {
	observed, err := adapter.observeIdentity(ctx, requested)
	if err != nil {
		return err
	}
	provider := adapter.config.Capability.Value().Provider
	if observed.RuntimeVersion != provider.RuntimeVersion || observed.ModelAlias != provider.ActualModel ||
		observed.TokenizerName != provider.TokenizerName || observed.TokenizerVersion != provider.TokenizerVersion ||
		observed.TokenizerDigest != provider.TokenizerDigest || observed.TemplateDigest != provider.ChatTemplateDigest || observed.ContextLimit != provider.ContextLimit {
		return newError(providercontract.Denied, "observed_identity_drift", false)
	}
	observation := LocalRouteObservation{Endpoint: adapter.config.Endpoint, RuntimeVersion: observed.RuntimeVersion,
		ExpectedRuntimeDigest: provider.RuntimeDigest, ExpectedImageDigest: provider.RuntimeDigest,
		ModelAlias: observed.ModelAlias, ModelRoot: observed.ModelRoot, ExpectedModelWeightsDigest: provider.ModelRevision,
		TokenizerDigest: observed.TokenizerDigest, ChatTemplateDigest: observed.TemplateDigest,
		ExpectedToolParserDigest: provider.ToolParserDigest, ExpectedReasoningParserDigest: provider.ReasoningParserDigest,
		ExpectedHardwareProfileDigest: provider.HardwareProfileDigest, ExpectedLaunchProfileDigest: provider.SamplingProfileDigest,
		RequiredStateMode: provider.StateMode}
	if err := adapter.config.Route.VerifyLocal(ctx, observation); err != nil {
		return newError(providercontract.Denied, "local_route_attestation_failed", false)
	}
	return nil
}

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[+.-][0-9A-Za-z.-]+)?$`)
