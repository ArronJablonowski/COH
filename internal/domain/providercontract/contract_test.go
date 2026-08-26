package providercontract

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const expectedCapabilityDigest = "sha256:0d58b09b1f641d043cf02e8c0b1cd130ab6886ca2d3695475cc9e07b3932f6bb"

func TestCanonicalCapabilityQualificationAndAdmission(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	qualification := decodeQualificationFixture(t)
	if capability.Digest() != expectedCapabilityDigest || qualification.Digest() == "" {
		t.Fatalf("digests capability=%s qualification=%s", capability.Digest(), qualification.Digest())
	}
	if err := AdmitQualification(capability, qualification, mustTime(t, "2026-08-26T06:00:00.000000000Z")); err != nil {
		t.Fatal(err)
	}
	canonical := capability.CanonicalBytes()
	canonical[0] = '['
	if capability.CanonicalBytes()[0] != '{' || capability.Value().Features.MessageRoles[0] != "assistant" {
		t.Fatal("validated capability exposed mutable state")
	}
	again, err := DecodeCapability(context.Background(), capability.CanonicalBytes())
	if err != nil || again.Digest() != capability.Digest() || !bytes.Equal(again.CanonicalBytes(), capability.CanonicalBytes()) {
		t.Fatalf("canonical recovery digest=%s err=%v", again.Digest(), err)
	}
}

func TestStrictCapabilityAndQualificationDenials(t *testing.T) {
	capabilityInput := readFixture(t, "capability.json")
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"limits": {`), []byte(`"extra": true, "limits": {`), 1)
		},
		"missing boolean": func(input []byte) []byte { return bytes.Replace(input, []byte("    \"usage\": true,\n"), nil, 1) },
		"duplicate": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"contract_version": "1.0.0",`), []byte(`"contract_version": "1.0.0", "contract_version": "1.0.0",`), 1)
		},
		"noninteger": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"context_limit": 32768`), []byte(`"context_limit": 32768.0`), 1)
		},
		"unsorted set": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"assistant", "developer"`), []byte(`"developer", "assistant"`), 1)
		},
	} {
		if _, err := DecodeCapability(context.Background(), mutate(append([]byte(nil), capabilityInput...))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	qualification := decodeQualificationFixture(t).Value()
	qualification.Provider.ModelRevision = digest("c")
	encoded, err := json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	drifted, err := DecodeQualification(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := AdmitQualification(decodeCapabilityFixture(t), drifted, mustTime(t, "2026-08-26T06:00:00.000000000Z")); Code(err) != Unsupported || Reason(err) != "provider_identity_drift" {
		t.Fatalf("identity drift err=%v", err)
	}
	if err := AdmitQualification(decodeCapabilityFixture(t), decodeQualificationFixture(t), mustTime(t, "2026-09-25T05:05:00.000000000Z")); Code(err) != Unsupported || Reason(err) != "qualification_expired" {
		t.Fatalf("expiry err=%v", err)
	}
}

func TestInferenceRoundTripAndStreamState(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	provider := capability.Value().Provider
	request := validRequest(provider, capability.Digest())
	validatedRequest := decodeRequest(t, request)
	response := validResponse(provider, capability.Digest(), request)
	validatedResponse := decodeResponse(t, response)
	if validatedRequest.Digest() == validatedResponse.Digest() || validatedResponse.Value().Usage.TotalTokens != 15 {
		t.Fatal("request/response digest or usage binding failed")
	}

	textEvent := StreamEvent{SchemaVersion: StreamEventSchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, AttemptID: request.AttemptID, Sequence: 0,
		ObservedAt: "2026-08-26T06:00:00.000000000Z", Kind: "text_delta", TextDelta: "ok"}
	completedEvent := StreamEvent{SchemaVersion: StreamEventSchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, AttemptID: request.AttemptID, Sequence: 1,
		ObservedAt: "2026-08-26T06:00:01.000000000Z", Kind: "completed", Response: &response}
	validator := &StreamValidator{}
	for _, event := range []StreamEvent{textEvent, completedEvent} {
		if err := validator.Apply(decodeEvent(t, event)); err != nil {
			t.Fatal(err)
		}
	}
	if !validator.Complete() {
		t.Fatal("terminal stream not complete")
	}
	if err := validator.Apply(decodeEvent(t, completedEvent)); Code(err) != Conflict || Reason(err) != "stream_after_terminal" {
		t.Fatalf("post-terminal err=%v", err)
	}
	bad := textEvent
	bad.Sequence = 2
	if err := (&StreamValidator{}).Apply(decodeEvent(t, bad)); Code(err) != Conflict || Reason(err) != "stream_sequence" {
		t.Fatalf("sequence err=%v", err)
	}
}

func TestInferenceDenialCancellationAndRecovery(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	request := validRequest(capability.Value().Provider, capability.Digest())
	request.Messages[0].Items[0].Kind = "tool_call"
	request.Messages[0].Items[0].CallID = "call-1"
	request.Messages[0].Items[0].ToolName = "collect"
	request.Messages[0].Items[0].Arguments = json.RawMessage(`{}`)
	request.Messages[0].Items[0].InputSchemaDigest = strings.Repeat("a", 64)
	if _, err := DecodeRequest(context.Background(), marshal(t, request)); err == nil {
		t.Fatal("role-incompatible and malformed tool call accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeCapability(ctx, readFixture(t, "capability.json")); Code(err) != Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
	if _, err := DecodeCapability(context.Background(), readFixture(t, "capability.json")); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

func TestPublicTypesHaveNoVendorPassthroughOrSecretSurface(t *testing.T) {
	for _, value := range []any{CapabilitySnapshot{}, QualificationRecord{}, InferenceRequest{}, InferenceResponse{}, StreamEvent{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			tag := strings.Split(typeOf.Field(index).Tag.Get("json"), ",")[0]
			for _, forbidden := range []string{"options", "headers", "passthrough", "api_key", "credential", "secret", "token"} {
				if tag == forbidden {
					t.Fatalf("%s exposes %s", typeOf.Name(), tag)
				}
			}
		}
	}
}

func decodeCapabilityFixture(t *testing.T) ValidatedCapability {
	t.Helper()
	value, err := DecodeCapability(context.Background(), readFixture(t, "capability.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func decodeQualificationFixture(t *testing.T) ValidatedQualification {
	t.Helper()
	value, err := DecodeQualification(context.Background(), readFixture(t, "qualification.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func decodeRequest(t *testing.T, value InferenceRequest) ValidatedRequest {
	t.Helper()
	result, err := DecodeRequest(context.Background(), marshal(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeResponse(t *testing.T, value InferenceResponse) ValidatedResponse {
	t.Helper()
	result, err := DecodeResponse(context.Background(), marshal(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeEvent(t *testing.T, value StreamEvent) ValidatedStreamEvent {
	t.Helper()
	result, err := DecodeStreamEvent(context.Background(), marshal(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func validRequest(provider ProviderIdentity, capabilityDigest string) InferenceRequest {
	return InferenceRequest{SchemaVersion: RequestSchemaVersion, ContractVersion: ContractVersion,
		RequestID: "0198e300-1000-7000-8000-000000000003", AttemptID: "0198e300-1000-7000-8000-000000000004",
		OrganizationID: "0198e300-1000-7000-8000-000000000005", TenantID: "0198e300-1000-7000-8000-000000000006",
		CaseID: "0198e300-1000-7000-8000-000000000007", TaskID: "0198e300-1000-7000-8000-000000000008",
		ActorID: "0198e300-1000-7000-8000-000000000009", Provider: provider, CapabilityDigest: capabilityDigest,
		QualificationID: "0198e300-1000-7000-8000-000000000002",
		Messages:        []Message{{MessageID: "0198e300-1000-7000-8000-000000000010", Role: "user", Items: []ContentItem{{Kind: "text", Text: "hello"}}}},
		Tools:           []Tool{}, OutputConstraint: OutputConstraint{Kind: "text"}, Sampling: Sampling{TemperatureMilli: 200, TopPMillionths: 900000, Seed: 7},
		MaximumOutputTokens: 1024, State: State{Mode: "stateless"}, Deadline: "2026-08-26T06:01:00.000000000Z",
		AuthorizationDigest: digest("a"), PolicyDecisionDigest: digest("b"), ApprovalDecisionDigest: digest("c"), AuditReservationDigest: digest("d")}
}

func validResponse(provider ProviderIdentity, capabilityDigest string, request InferenceRequest) InferenceResponse {
	return InferenceResponse{SchemaVersion: ResponseSchemaVersion, ContractVersion: ContractVersion,
		ResponseID: "0198e300-1000-7000-8000-000000000011", RequestID: request.RequestID, AttemptID: request.AttemptID,
		Provider: provider, CapabilityDigest: capabilityDigest, QualificationID: request.QualificationID, Outcome: "succeeded",
		Items: []ContentItem{{Kind: "text", Text: "ok"}}, Usage: Usage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15, ReasoningTokens: 2},
		State: State{Mode: "stateless"}, StartedAt: "2026-08-26T06:00:00.000000000Z", CompletedAt: "2026-08-26T06:00:01.000000000Z",
		ProvenanceDigest: digest("e")}
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("../../../contracts/provider/v1/fixtures/valid/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
