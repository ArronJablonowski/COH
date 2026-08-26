package contextcompact

import (
	"reflect"
	"strings"
	"testing"
)

func TestPublicCompactionSurfaceCannotCarryInstructionOrActionAuthority(t *testing.T) {
	for _, value := range []any{Source{}, Intent{}, State{}, Result{}, SummaryRequest{}, EvidenceLookup{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"prompt", "instruction", "content", "credential", "secret",
				"approval", "policyauthority", "toolauthority", "connector", "executor", "callback"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("unsafe public field %s.%s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable public field %s.%s: %v", typeOf.Name(), field.Name, field.Type)
			}
		}
	}

	compactor := reflect.TypeOf((*Compactor)(nil)).Elem()
	writer := reflect.TypeOf((*SummaryWriter)(nil)).Elem()
	resolver := reflect.TypeOf((*EvidenceResolver)(nil)).Elem()
	if compactor.NumMethod() != 1 || compactor.Method(0).Name != "Compact" ||
		writer.NumMethod() != 1 || writer.Method(0).Name != "Write" ||
		resolver.NumMethod() != 1 || resolver.Method(0).Name != "Resolve" {
		t.Fatalf("compactor=%v writer=%v resolver=%v", compactor, writer, resolver)
	}
	requestType := writer.Method(0).Type.In(1)
	if requestType != reflect.TypeOf(SummaryRequest{}) {
		t.Fatalf("writer request=%v", requestType)
	}
}
