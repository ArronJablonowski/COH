package ollama

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

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
		ContextLimit: contextLimit, Capabilities: capabilities}, nil
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
	if !validText(result.ModifiedAt, 128) || result.Size == 0 || !validDetails(result.Details) {
		return modelRecord{}, newError(providercontract.InvalidInput, "model_record_invalid", false)
	}
	return result, nil
}

func validateShow(show showResponse, record modelRecord) (uint64, string, error) {
	if show.Template == "" || len(show.Template) > 1<<20 || show.ModifiedAt != record.ModifiedAt ||
		!equalDetails(show.Details, record.Details) || len(show.Capabilities) == 0 || len(show.ModelInfo) == 0 {
		return 0, "", newError(providercontract.Denied, "model_metadata_invalid", false)
	}
	seen := make(map[string]struct{}, len(show.Capabilities))
	for _, capability := range show.Capabilities {
		if !validText(capability, 64) {
			return 0, "", newError(providercontract.InvalidInput, "model_capability_invalid", false)
		}
		seen[capability] = struct{}{}
	}
	if len(seen) != len(show.Capabilities) {
		return 0, "", newError(providercontract.Conflict, "model_capability_duplicate", false)
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
	canonical, err := json.Marshal(show.ModelInfo)
	if err != nil || matches != 1 {
		return 0, "", newError(providercontract.InvalidInput, "model_info_invalid", false)
	}
	canonical, err = canonicalJSON(canonical)
	if err != nil {
		return 0, "", err
	}
	return contextLimit, digest(modelInfoDomain, canonical), nil
}

func validDetails(value modelDetails) bool {
	return validText(value.Format, 64) && validText(value.Family, 128) && len(value.Families) > 0 &&
		validText(value.ParameterSize, 64) && validText(value.QuantizationLevel, 64)
}

func equalDetails(left, right modelDetails) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
