package caselifecycle

import (
	"reflect"
	"strings"
	"testing"
)

func TestCaseLifecycleRecordsCarryNoContentOrExecutableAuthority(t *testing.T) {
	for _, value := range []any{Command{}, AuthorizationRequest{}, Decision{}, Record{}, Receipt{}, Result{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"content", "bytes", "prompt", "instruction", "credential", "secret",
				"policy_source", "approval", "connector", "executor", "callback", "shell", "http", "url", "uri", "path"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("unsafe public field %s.%s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable public field %s.%s", typeOf.Name(), field.Name)
			}
		}
	}
}

func TestCaseLifecyclePortsRemainNarrow(t *testing.T) {
	tests := []struct {
		name    string
		value   reflect.Type
		methods []string
	}{
		{"authority", reflect.TypeOf((*Authority)(nil)).Elem(), []string{"AuthorizeCase"}},
		{"auditor", reflect.TypeOf((*Auditor)(nil)).Elem(), []string{"AppendAuditEvent"}},
		{"store", reflect.TypeOf((*Store)(nil)).Elem(), []string{"Commit", "Load", "Recover"}},
		{"clock", reflect.TypeOf((*Clock)(nil)).Elem(), []string{"Now"}},
	}
	for _, test := range tests {
		if test.value.NumMethod() != len(test.methods) {
			t.Fatalf("%s methods=%d", test.name, test.value.NumMethod())
		}
		for index, name := range test.methods {
			if test.value.Method(index).Name != name {
				t.Fatalf("%s method[%d]=%s", test.name, index, test.value.Method(index).Name)
			}
		}
	}
}
