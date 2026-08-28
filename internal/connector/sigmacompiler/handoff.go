package sigmacompiler

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	NativeValidationRequestVersion = "coh.sigma-native-validation-request/v1"
	NativeValidationReceiptVersion = "coh.sigma-native-validation-receipt/v1"
	ElasticValidatorID             = "elastic-esql-1.0.0"
	SplunkValidatorID              = "splunk-parser-1.0.0+native-preflight"
	SentinelValidatorID            = "kusto-language-12.4.1-coh-1.0.0"
)

// NativeValidationRequest is created only after the current mapping and
// discovered schema have been rebound to a strict compiled response.
type NativeValidationRequest struct {
	SchemaVersion             string        `json:"schema_version"`
	ContractVersion           string        `json:"contract_version"`
	RequestID                 string        `json:"request_id"`
	CompilationResponseDigest string        `json:"compilation_response_digest"`
	Target                    TargetBinding `json:"target"`
	TargetResource            string        `json:"target_resource"`
	MappingID                 string        `json:"mapping_id"`
	MappingRevision           uint64        `json:"mapping_revision"`
	MappingDigest             string        `json:"mapping_digest"`
	DiscoveredSchemaDigest    string        `json:"discovered_schema_digest"`
	NativeQuery               string        `json:"native_query"`
	NativeQueryDigest         string        `json:"native_query_digest"`
	InputState                string        `json:"input_state"`
}

// NativeValidationReceipt deliberately contains no native query or source
// rule. It proves which parser accepted which digest-bound handoff.
type NativeValidationReceipt struct {
	SchemaVersion             string   `json:"schema_version"`
	ContractVersion           string   `json:"contract_version"`
	RequestID                 string   `json:"request_id"`
	CompilationResponseDigest string   `json:"compilation_response_digest"`
	Target                    string   `json:"target"`
	ValidatorID               string   `json:"validator_id"`
	MappingDigest             string   `json:"mapping_digest"`
	DiscoveredSchemaDigest    string   `json:"discovered_schema_digest"`
	NativeQueryDigest         string   `json:"native_query_digest"`
	Outcome                   string   `json:"outcome"`
	ReasonCodes               []string `json:"reason_codes"`
	State                     string   `json:"state"`
	ReceiptDigest             string   `json:"receipt_digest"`
}

type NativeValidator interface {
	ValidatorID() string
	ValidateCompiledNative(context.Context, NativeValidationRequest) (NativeValidationReceipt, error)
}

type TargetValidators struct {
	Elastic  NativeValidator
	Splunk   NativeValidator
	Sentinel NativeValidator
}

type NativeHandoff struct{ validators TargetValidators }

func NewNativeHandoff(validators TargetValidators) (*NativeHandoff, error) {
	if validators.Elastic == nil || validators.Elastic.ValidatorID() != ElasticValidatorID ||
		validators.Splunk == nil || validators.Splunk.ValidatorID() != SplunkValidatorID ||
		validators.Sentinel == nil || validators.Sentinel.ValidatorID() != SentinelValidatorID {
		return nil, nativeError(queryconnector.InvalidInput, "sigma_native_validators_required", nil)
	}
	return &NativeHandoff{validators: validators}, nil
}

// Validate rechecks the compiler exchange, rebinds the discovered schema, and
// returns only a verified receipt. The query remains confined to the selected
// native validator.
func (handoff *NativeHandoff) Validate(ctx context.Context, request CompileRequest, response CompileResponse,
	discoveredSchemaDigest string) (NativeValidationReceipt, error) {
	if handoff == nil {
		return NativeValidationReceipt{}, nativeError(queryconnector.Unavailable, "sigma_native_handoff_unavailable", nil)
	}
	if err := nativeContextError(ctx); err != nil {
		return NativeValidationReceipt{}, err
	}
	if ValidateExchange(request, response) != nil || response.Outcome != "compiled_untrusted" ||
		response.NativeQuery == "" || response.NativeQueryDigest == "" {
		return NativeValidationReceipt{}, nativeError(queryconnector.Denied, "sigma_not_compiled", nil)
	}
	if discoveredSchemaDigest != request.Mapping.TargetSchemaDigest || discoveredSchemaDigest != response.TargetSchemaDigest {
		return NativeValidationReceipt{}, nativeError(queryconnector.Denied, "sigma_schema_rebind_required", nil)
	}
	validator := handoff.validator(response.Target.Target)
	if validator == nil {
		return NativeValidationReceipt{}, nativeError(queryconnector.Unsupported, "sigma_native_validator_unavailable", nil)
	}
	input := NativeValidationRequest{SchemaVersion: NativeValidationRequestVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, CompilationResponseDigest: response.ResponseDigest, Target: response.Target,
		TargetResource: request.Mapping.TargetResource, MappingID: request.Mapping.MappingID,
		MappingRevision: request.Mapping.Revision, MappingDigest: request.Mapping.MappingDigest,
		DiscoveredSchemaDigest: discoveredSchemaDigest, NativeQuery: response.NativeQuery,
		NativeQueryDigest: response.NativeQueryDigest, InputState: "compiled_untrusted"}
	receipt, err := validator.ValidateCompiledNative(ctx, input)
	if err != nil {
		if contextErr := nativeContextError(ctx); contextErr != nil {
			return NativeValidationReceipt{}, contextErr
		}
		return NativeValidationReceipt{}, nativeError(queryconnector.Denied, "sigma_native_validation_denied", err)
	}
	if !validNativeReceipt(input, validator.ValidatorID(), receipt) {
		return NativeValidationReceipt{}, nativeError(queryconnector.Denied, "sigma_native_receipt_denied", nil)
	}
	return cloneNativeReceipt(receipt), nil
}

func (handoff *NativeHandoff) validator(target string) NativeValidator {
	switch target {
	case "elastic":
		return handoff.validators.Elastic
	case "splunk":
		return handoff.validators.Splunk
	case "sentinel":
		return handoff.validators.Sentinel
	default:
		return nil
	}
}

func NativeValidationReceiptDigest(value NativeValidationReceipt) string {
	value.ReceiptDigest = ""
	return digest("COH-SIGMA-NATIVE-VALIDATION-RECEIPT-V1\x00", value)
}

func validNativeReceipt(input NativeValidationRequest, validatorID string, receipt NativeValidationReceipt) bool {
	return receipt.SchemaVersion == NativeValidationReceiptVersion && receipt.ContractVersion == ContractVersion &&
		receipt.RequestID == input.RequestID && receipt.CompilationResponseDigest == input.CompilationResponseDigest &&
		receipt.Target == input.Target.Target && receipt.ValidatorID == validatorID &&
		receipt.MappingDigest == input.MappingDigest && receipt.DiscoveredSchemaDigest == input.DiscoveredSchemaDigest &&
		receipt.NativeQueryDigest == input.NativeQueryDigest && receipt.Outcome == "accepted" &&
		len(receipt.ReasonCodes) == 0 && receipt.State == "native_validated" &&
		receipt.ReceiptDigest == NativeValidationReceiptDigest(receipt)
}

func cloneNativeReceipt(value NativeValidationReceipt) NativeValidationReceipt {
	value.ReasonCodes = slices.Clone(value.ReasonCodes)
	return value
}
