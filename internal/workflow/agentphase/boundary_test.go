package agentphase

import (
	"reflect"
	"testing"

	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

func TestCoordinatorDependencySurfaceHasNoActionBypass(t *testing.T) {
	dependencies := reflect.TypeOf(Dependencies{})
	want := map[string]reflect.Type{
		"Store":   reflect.TypeOf((*agentloop.StateStore)(nil)).Elem(),
		"Models":  reflect.TypeOf((*workflowbase.ModelProvider)(nil)).Elem(),
		"Actions": reflect.TypeOf((*workflowbase.ActionAuthority)(nil)).Elem(),
		"Results": reflect.TypeOf((*ResultResolver)(nil)).Elem(),
		"Clock":   reflect.TypeOf((*agentloop.Clock)(nil)).Elem(),
	}
	if dependencies.NumField() != len(want) {
		t.Fatalf("dependencies=%v", dependencies)
	}
	for index := 0; index < dependencies.NumField(); index++ {
		field := dependencies.Field(index)
		if want[field.Name] != field.Type || field.Type.Kind() == reflect.Func {
			t.Fatalf("unexpected dependency: %s %v", field.Name, field.Type)
		}
	}
	coordinator := reflect.TypeOf(Coordinator{})
	for index := 0; index < coordinator.NumField(); index++ {
		field := coordinator.Field(index)
		if field.Type.Kind() == reflect.Func || field.Name == "connector" || field.Name == "executor" ||
			field.Name == "runner" || field.Name == "credential" || field.Name == "policy" {
			t.Fatalf("unsafe coordinator field: %s %v", field.Name, field.Type)
		}
	}
}
