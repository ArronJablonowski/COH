package sigmacompiler

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type nativeValidatorStub struct {
	id      string
	calls   []NativeValidationRequest
	mutate  func(*NativeValidationReceipt)
	failure error
}

func (validator *nativeValidatorStub) ValidatorID() string { return validator.id }

func (validator *nativeValidatorStub) ValidateCompiledNative(_ context.Context,
	input NativeValidationRequest) (NativeValidationReceipt, error) {
	validator.calls = append(validator.calls, input)
	if validator.failure != nil {
		return NativeValidationReceipt{}, validator.failure
	}
	receipt := NativeValidationReceipt{SchemaVersion: NativeValidationReceiptVersion, ContractVersion: ContractVersion,
		RequestID: input.RequestID, CompilationResponseDigest: input.CompilationResponseDigest,
		Target: input.Target.Target, ValidatorID: validator.id, MappingDigest: input.MappingDigest,
		DiscoveredSchemaDigest: input.DiscoveredSchemaDigest, NativeQueryDigest: input.NativeQueryDigest,
		Outcome: "accepted", ReasonCodes: []string{}, State: "native_validated"}
	if validator.mutate != nil {
		validator.mutate(&receipt)
	}
	receipt.ReceiptDigest = NativeValidationReceiptDigest(receipt)
	return receipt, nil
}

func TestNativeHandoffRoutesEveryQualifiedBackendAndReleasesOnlyReceipt(t *testing.T) {
	elastic := &nativeValidatorStub{id: ElasticValidatorID}
	splunk := &nativeValidatorStub{id: SplunkValidatorID}
	sentinel := &nativeValidatorStub{id: SentinelValidatorID}
	handoff, err := NewNativeHandoff(TargetValidators{Elastic: elastic, Splunk: splunk, Sentinel: sentinel})
	if err != nil {
		t.Fatal(err)
	}
	validators := map[string]*nativeValidatorStub{"elastic": elastic, "splunk": splunk, "sentinel": sentinel}
	for _, target := range targetMatrix {
		if target.Target == "security-onion" {
			continue
		}
		request := testRequest()
		request.Target = target
		request.RequestDigest = CompileRequestDigest(request)
		response := testResponse(request)
		receipt, validateErr := handoff.Validate(context.Background(), request, response, request.Mapping.TargetSchemaDigest)
		if validateErr != nil || receipt.State != "native_validated" || receipt.NativeQueryDigest != response.NativeQueryDigest ||
			receipt.ReceiptDigest != NativeValidationReceiptDigest(receipt) {
			t.Fatalf("%s handoff denied: receipt=%+v err=%v", target.Target, receipt, validateErr)
		}
		validator := validators[target.Target]
		if len(validator.calls) != 1 || validator.calls[0].InputState != "compiled_untrusted" ||
			validator.calls[0].NativeQuery != response.NativeQuery || validator.calls[0].MappingRevision != request.Mapping.Revision {
			t.Fatalf("%s native binding lost: %+v", target.Target, validator.calls)
		}
	}
}

func TestNativeHandoffWithholdsQueryOnSchemaDriftAndUnsupportedCompilation(t *testing.T) {
	elastic := &nativeValidatorStub{id: ElasticValidatorID}
	handoff := testNativeHandoff(t, elastic)
	request := testRequest()
	response := testResponse(request)
	if receipt, err := handoff.Validate(context.Background(), request, response, repeatDigest("0")); queryconnector.Reason(err) != "sigma_schema_rebind_required" || !reflect.DeepEqual(receipt, NativeValidationReceipt{}) || len(elastic.calls) != 0 {
		t.Fatalf("schema drift reached validator: receipt=%+v err=%v calls=%d", receipt, err, len(elastic.calls))
	}
	unsupported := testNeedsMappingResponse(request)
	if receipt, err := handoff.Validate(context.Background(), request, unsupported, request.Mapping.TargetSchemaDigest); queryconnector.Reason(err) != "sigma_not_compiled" || !reflect.DeepEqual(receipt, NativeValidationReceipt{}) || len(elastic.calls) != 0 {
		t.Fatalf("unsupported conversion released query: receipt=%+v err=%v calls=%d", receipt, err, len(elastic.calls))
	}
}

func TestNativeHandoffDeniesValidatorAndReceiptSubstitution(t *testing.T) {
	request := testRequest()
	response := testResponse(request)
	for name, validator := range map[string]*nativeValidatorStub{
		"denial": {id: ElasticValidatorID, failure: errors.New("parser denied")},
		"receipt": {id: ElasticValidatorID, mutate: func(value *NativeValidationReceipt) {
			value.MappingDigest = repeatDigest("0")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			handoff := testNativeHandoff(t, validator)
			receipt, err := handoff.Validate(context.Background(), request, response, request.Mapping.TargetSchemaDigest)
			if queryconnector.Code(err) != queryconnector.Denied || !reflect.DeepEqual(receipt, NativeValidationReceipt{}) {
				t.Fatalf("validator substitution released receipt: %+v %v", receipt, err)
			}
		})
	}
}

func testNativeHandoff(t *testing.T, elastic NativeValidator) *NativeHandoff {
	t.Helper()
	handoff, err := NewNativeHandoff(TargetValidators{Elastic: elastic,
		Splunk: &nativeValidatorStub{id: SplunkValidatorID}, Sentinel: &nativeValidatorStub{id: SentinelValidatorID}})
	if err != nil {
		t.Fatal(err)
	}
	return handoff
}
