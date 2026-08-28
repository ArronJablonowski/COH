package modelsurface

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func TestAdmitInferenceBindsExactSurfaceAndProviderRequest(t *testing.T) {
	fixture := newProjectionFixture(t)
	surface, err := fixture.projector.Project(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	template := validProviderTemplate()
	admitted, err := AdmitInference(context.Background(), surface, template)
	if err != nil {
		t.Fatalf("AdmitInference() error = %v", err)
	}
	request := admitted.Request().Value()
	binding := admitted.Binding()
	projection := surface.Projection()
	if request.ModelSurface.BindingDigest != binding.BindingDigest || binding.ProjectionDigest != projection.ProjectionDigest ||
		request.ModelSurface.SurfaceDigest != projection.SurfaceDigest || request.ModelSurface.ProviderID != "ollama.local" {
		t.Fatalf("request surface=%#v binding=%#v", request.ModelSurface, binding)
	}
	if len(request.Messages) != 5 || len(request.Tools) != 1 || request.Tools[0].Name != "query.host" {
		t.Fatalf("messages=%#v tools=%#v", request.Messages, request.Tools)
	}
	for index, message := range request.Messages[:3] {
		if message.MessageID != projection.OrderedSourceRecordIDs[index] {
			t.Fatalf("message[%d]=%#v", index, message)
		}
	}
	if request.Messages[3].Items[0].Kind != "input_json" || request.Messages[3].Role != "user" ||
		request.Messages[4].Items[0].Kind != "text" || request.Messages[4].Role != "user" {
		t.Fatalf("data messages=%#v", request.Messages[3:])
	}
	request.Messages[0].Items[0].Text = "mutated"
	binding.OrderedSourceRecordIDs[0] = uuid(99)
	if admitted.Request().Value().Messages[0].Items[0].Text == "mutated" || admitted.Binding().OrderedSourceRecordIDs[0] == uuid(99) {
		t.Fatal("admitted inference aliases caller mutation")
	}
}

func TestAdmitInferenceDeniesAlternateOrDriftedSurface(t *testing.T) {
	newSurface := func(t *testing.T) ProjectedSurface {
		fixture := newProjectionFixture(t)
		value, err := fixture.projector.Project(context.Background(), fixture.request)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	tests := []struct {
		name   string
		mutate func(*ProjectedSurface, *providercontract.InferenceRequest)
		reason string
	}{
		{"caller messages", func(_ *ProjectedSurface, request *providercontract.InferenceRequest) {
			request.Messages = []providercontract.Message{{}}
		}, "caller_visible_surface"},
		{"caller binding", func(_ *ProjectedSurface, request *providercontract.InferenceRequest) {
			request.ModelSurface.BindingDigest = digest('1')
		}, "caller_visible_surface"},
		{"scope drift", func(_ *ProjectedSurface, request *providercontract.InferenceRequest) { request.TenantID = uuid(91) }, "dispatch_scope"},
		{"item drift", func(surface *ProjectedSurface, _ *providercontract.InferenceRequest) {
			surface.items[0].Content = []byte(`"drift"`)
		}, "projection_items"},
		{"projection drift", func(surface *ProjectedSurface, _ *providercontract.InferenceRequest) {
			surface.projectionBytes[0] = 'x'
		}, "projection_seal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			surface, request := newSurface(t), validProviderTemplate()
			test.mutate(&surface, &request)
			if _, err := AdmitInference(context.Background(), surface, request); Code(err) != Denied || Reason(err) != test.reason {
				t.Fatalf("err=%v code=%s reason=%s", err, Code(err), Reason(err))
			}
		})
	}
}

func validProviderTemplate() providercontract.InferenceRequest {
	scope := validScopeValue()
	return providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion, ContractVersion: providercontract.ContractVersion,
		RequestID: uuid(70), AttemptID: uuid(71), OrganizationID: scope.OrganizationID, TenantID: scope.TenantID,
		CaseID: scope.CaseID, TaskID: scope.TaskID, ActorID: uuid(72), Provider: providercontract.ProviderIdentity{
			ProviderKind: "ollama", AdapterVersion: "1.0.0", EndpointIdentityDigest: digest('1'), DataRoute: "local",
			RequestedModel: "qwen3:8b", ActualModel: "qwen3:8b", ModelRevision: digest('2'), RuntimeName: "ollama",
			RuntimeVersion: "1.0.0", RuntimeDigest: digest('3'), TokenizerName: "qwen3", TokenizerVersion: "1.0.0",
			TokenizerDigest: digest('4'), ChatTemplateDigest: digest('5'), ToolParserDigest: digest('6'), ReasoningParserDigest: digest('7'),
			ContextLimit: 32768, SamplingProfileDigest: digest('8'), HardwareProfileDigest: digest('9'), StateMode: "stateless", PolicyRevision: 1},
		CapabilityDigest: digest('a'), QualificationID: uuid(73), OutputConstraint: providercontract.OutputConstraint{Kind: "text"},
		Sampling: providercontract.Sampling{TopPMillionths: 1000000}, MaximumOutputTokens: 1024,
		State: providercontract.State{Mode: "stateless"}, Deadline: timestamp(20), AuthorizationDigest: digest('b'),
		PolicyDecisionDigest: digest('c'), ApprovalDecisionDigest: digest('d'), AuditReservationDigest: digest('e')}
}
