package ollama

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type modelMetadataWire struct {
	Capabilities    []string                   `json:"capabilities"`
	ModelInfo       map[string]json.RawMessage `json:"model_info"`
	ModelfileDigest string                     `json:"modelfile_digest"`
	ProjectorInfo   map[string]json.RawMessage `json:"projector_info"`
	Requires        string                     `json:"requires"`
	Tensors         []tensorRecord             `json:"tensors"`
	TagDetails      modelDetails               `json:"tag_details"`
}

const (
	runtimeDigestDomain  = "COH-OLLAMA-RUNTIME-V1\x00"
	templateDigestDomain = "COH-OLLAMA-TEMPLATE-V1\x00"
	modelInfoDomain      = "COH-OLLAMA-MODEL-INFO-V1\x00"
)

type observedIdentity struct {
	RuntimeVersion  string
	RuntimeDigest   string
	Model           string
	ModelRevision   string
	TemplateDigest  string
	ModelInfoDigest string
	TokenizerName   string
	ContextLimit    uint64
	Capabilities    []string
}

func (adapter *Adapter) observeIdentity(ctx context.Context, model string) (observedIdentity, error) {
	var version versionResponse
	if _, err := adapter.getJSON(ctx, VersionPath, &version); err != nil {
		return observedIdentity{}, err
	}
	if !validText(version.Version, 64) {
		return observedIdentity{}, newError(providercontract.InvalidInput, "runtime_version_invalid", false)
	}
	var tags tagsResponse
	if _, err := adapter.getJSON(ctx, TagsPath, &tags); err != nil {
		return observedIdentity{}, err
	}
	record, err := exactModelRecord(tags.Models, model)
	if err != nil {
		return observedIdentity{}, err
	}
	var show showResponse
	if _, err := adapter.postJSON(ctx, ShowPath, showRequest{Model: model, Verbose: false}, &show); err != nil {
		return observedIdentity{}, err
	}
	contextLimit, infoDigest, err := validateShow(show, record)
	if err != nil {
		return observedIdentity{}, err
	}
	capabilities := append([]string(nil), show.Capabilities...)
	sort.Strings(capabilities)
	return observedIdentity{RuntimeVersion: version.Version, RuntimeDigest: digest(runtimeDigestDomain, []byte(version.Version)),
		Model: record.Model, ModelRevision: "sha256:" + record.Digest,
		TemplateDigest: digest(templateDigestDomain, []byte(show.Template)), ModelInfoDigest: infoDigest,
		TokenizerName: show.Details.Family, ContextLimit: contextLimit, Capabilities: capabilities}, nil
}

// ObserveLocalIdentity discovers the exact loopback runtime, model revision,
// tokenizer metadata, template, and parser tuple used to construct a
// capability snapshot. It performs no model inference or qualification.
func ObserveLocalIdentity(ctx context.Context, model string, client HTTPDoer,
	hardwareProfileDigest string, policyRevision uint64) (LocalIdentityObservation, error) {
	if ctx == nil || model == "" || client == nil {
		return LocalIdentityObservation{}, newError(providercontract.InvalidInput, "identity_observation_input", false)
	}
	observed, err := (&Adapter{config: Config{Endpoint: OllamaEndpoint, HTTP: client}}).observeIdentity(ctx, model)
	if err != nil {
		return LocalIdentityObservation{}, err
	}
	identity := providercontract.ProviderIdentity{ProviderKind: "ollama", AdapterVersion: AdapterVersion,
		EndpointIdentityDigest: EndpointIdentityDigest(OllamaEndpoint), DataRoute: "local", RequestedModel: model,
		ActualModel: observed.Model, ModelRevision: observed.ModelRevision, RuntimeName: "ollama",
		RuntimeVersion: observed.RuntimeVersion, RuntimeDigest: observed.RuntimeDigest, TokenizerName: observed.TokenizerName,
		TokenizerVersion: observed.RuntimeVersion, TokenizerDigest: observed.ModelInfoDigest,
		ChatTemplateDigest: observed.TemplateDigest, ToolParserDigest: ToolParserDigest(),
		ReasoningParserDigest: ReasoningParserDigest(), ContextLimit: observed.ContextLimit,
		SamplingProfileDigest: SamplingProfileDigest(), HardwareProfileDigest: hardwareProfileDigest,
		StateMode: "stateless", PolicyRevision: policyRevision}
	return LocalIdentityObservation{Provider: identity,
		Capabilities: append([]string(nil), observed.Capabilities...)}, nil
}

func (adapter *Adapter) verifyIdentity(ctx context.Context, requested string) error {
	observed, err := adapter.observeIdentity(ctx, requested)
	if err != nil {
		return err
	}
	provider := adapter.config.Capability.Value().Provider
	if observed.RuntimeVersion != provider.RuntimeVersion || observed.RuntimeDigest != provider.RuntimeDigest ||
		observed.Model != provider.ActualModel || observed.ModelRevision != provider.ModelRevision ||
		observed.TemplateDigest != provider.ChatTemplateDigest || observed.ModelInfoDigest != provider.TokenizerDigest ||
		observed.ContextLimit != provider.ContextLimit || !contains(observed.Capabilities, "completion") ||
		!contains(observed.Capabilities, "tools") || !contains(observed.Capabilities, "thinking") {
		return newError(providercontract.Denied, "observed_identity_drift", false)
	}
	observation := LocalRouteObservation{Endpoint: adapter.config.Endpoint, RuntimeVersion: observed.RuntimeVersion,
		Model: observed.Model, ModelRevision: observed.ModelRevision}
	if err := adapter.config.Route.VerifyLocal(ctx, observation); err != nil {
		return newError(providercontract.Denied, "local_route_attestation_failed", false)
	}
	return nil
}

func exactModelRecord(models []modelRecord, wanted string) (modelRecord, error) {
	var result modelRecord
	matches := 0
	for _, model := range models {
		if model.Name == wanted || model.Model == wanted {
			result, matches = model, matches+1
		}
	}
	if matches != 1 || result.Name != wanted || result.Model != wanted || len(result.Digest) != 64 {
		return modelRecord{}, newError(providercontract.Denied, "model_identity_ambiguous", false)
	}
	for _, character := range result.Digest {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return modelRecord{}, newError(providercontract.InvalidInput, "model_digest_invalid", false)
		}
	}
	if !validText(result.ModifiedAt, 128) || result.Size == 0 || !validTagDetails(result.Details) {
		return modelRecord{}, newError(providercontract.InvalidInput, "model_record_invalid", false)
	}
	if len(result.Capabilities) > 32 || !validStringSet(result.Capabilities, 64) {
		return modelRecord{}, newError(providercontract.InvalidInput, "model_capability_invalid", false)
	}
	return result, nil
}

func validateShow(show showResponse, record modelRecord) (uint64, string, error) {
	if show.Template == "" || len(show.Template) > 1<<20 || show.ModifiedAt != record.ModifiedAt ||
		!validShowDetails(show.Details) || !compatibleDetails(show.Details, record.Details) ||
		len(show.Capabilities) == 0 || len(show.ModelInfo) == 0 {
		return 0, "", newError(providercontract.Denied, "model_metadata_invalid", false)
	}
	if !validStringSet(show.Capabilities, 64) {
		return 0, "", newError(providercontract.Conflict, "model_capability_duplicate", false)
	}
	if len(record.Capabilities) > 0 && !equalStringSet(record.Capabilities, show.Capabilities) {
		return 0, "", newError(providercontract.Denied, "model_capability_drift", false)
	}
	if len(show.Modelfile) > 1<<20 || !utf8.ValidString(show.Modelfile) ||
		show.Requires != "" && !validText(show.Requires, 64) || len(show.ProjectorInfo) > 4096 || len(show.Tensors) > 16384 {
		return 0, "", newError(providercontract.InvalidInput, "model_metadata_invalid", false)
	}
	for _, tensor := range show.Tensors {
		if !validText(tensor.Name, 512) || !validText(tensor.Type, 64) || len(tensor.Shape) == 0 || len(tensor.Shape) > 8 {
			return 0, "", newError(providercontract.InvalidInput, "model_tensor_invalid", false)
		}
		for _, dimension := range tensor.Shape {
			if dimension == 0 {
				return 0, "", newError(providercontract.InvalidInput, "model_tensor_invalid", false)
			}
		}
	}
	contextLimit, matches := uint64(0), 0
	for key, raw := range show.ModelInfo {
		if strings.HasSuffix(key, ".context_length") {
			var number json.Number
			if err := json.Unmarshal(raw, &number); err != nil {
				return 0, "", newError(providercontract.InvalidInput, "model_context_invalid", false)
			}
			parsed, err := strconv.ParseUint(number.String(), 10, 64)
			if err != nil || parsed == 0 {
				return 0, "", newError(providercontract.InvalidInput, "model_context_invalid", false)
			}
			contextLimit, matches = parsed, matches+1
		}
	}
	capabilities := append([]string(nil), show.Capabilities...)
	sort.Strings(capabilities)
	metadata := modelMetadataWire{Capabilities: capabilities, ModelInfo: show.ModelInfo,
		ModelfileDigest: digest("COH-OLLAMA-MODELFILE-V1\x00", []byte(show.Modelfile)),
		ProjectorInfo:   show.ProjectorInfo, Requires: show.Requires, Tensors: show.Tensors, TagDetails: record.Details}
	if record.Details.ContextLength != 0 && record.Details.ContextLength != contextLimit {
		return 0, "", newError(providercontract.Denied, "model_context_drift", false)
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || matches != 1 {
		return 0, "", newError(providercontract.InvalidInput, "model_info_invalid", false)
	}
	canonical, err = canonicalJSON(canonical)
	if err != nil {
		return 0, "", err
	}
	return contextLimit, digest(modelInfoDomain, canonical), nil
}

func validStringSet(values []string, maximum int) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validText(value, maximum) {
			return false
		}
		seen[value] = struct{}{}
	}
	return len(seen) == len(values)
}

func equalStringSet(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return slices.Equal(left, right)
}

func validTagDetails(value modelDetails) bool {
	return validText(value.Format, 64) && validOptionalText(value.ParentModel, 128) &&
		validOptionalText(value.Family, 128) && validStringSet(value.Families, 128) &&
		validOptionalText(value.ParameterSize, 64) && validOptionalText(value.QuantizationLevel, 64)
}

func validShowDetails(value modelDetails) bool {
	return validText(value.Format, 64) && validOptionalText(value.ParentModel, 128) && validText(value.Family, 128) &&
		validStringSet(value.Families, 128) && validText(value.ParameterSize, 64) && validText(value.QuantizationLevel, 64)
}

func compatibleDetails(show, tag modelDetails) bool {
	return show.Format == tag.Format && (tag.ParentModel == "" || show.ParentModel == tag.ParentModel) &&
		(tag.Family == "" || show.Family == tag.Family) && (len(tag.Families) == 0 || slices.Equal(show.Families, tag.Families)) &&
		(tag.ParameterSize == "" || show.ParameterSize == tag.ParameterSize) &&
		(tag.QuantizationLevel == "" || show.QuantizationLevel == tag.QuantizationLevel)
}

func validOptionalText(value string, maximum int) bool {
	return value == "" || validText(value, maximum)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
