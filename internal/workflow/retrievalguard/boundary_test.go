package retrievalguard

import (
	"reflect"
	"strings"
	"testing"
)

func TestPublicRetrievalRecordsContainNoInstructionOrAuthoritySurface(t *testing.T) {
	for _, value := range []any{Source{}, InspectionProfile{}, Request{}, AuthorizationRequest{}, Decision{}, Finding{}, InspectionRequest{}, InspectionResult{}, Record{}, Result{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"prompt", "instruction_text", "raw_content", "raw_bytes", "payload_bytes", "credential_value", "secret_value", "approval", "scope_override", "policy_source", "path", "uri", "url", "callback", "connector", "executor", "command"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("unsafe field %s.%s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable field %s.%s", typeOf.Name(), field.Name)
			}
		}
	}
}
func TestInspectorAndVerifierAreDataOnlyNarrowPorts(t *testing.T) {
	inspector := reflect.TypeOf((*Inspector)(nil)).Elem()
	verifier := reflect.TypeOf((*ArtifactVerifier)(nil)).Elem()
	authority := reflect.TypeOf((*Authority)(nil)).Elem()
	if inspector.NumMethod() != 1 || inspector.Method(0).Name != "Inspect" || verifier.NumMethod() != 1 || verifier.Method(0).Name != "VerifyArtifact" || authority.NumMethod() != 1 || authority.Method(0).Name != "AuthorizeRetrieval" {
		t.Fatalf("inspector=%v verifier=%v authority=%v", inspector, verifier, authority)
	}
}
