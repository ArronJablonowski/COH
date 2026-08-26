package memorynamespace

import (
	"reflect"
	"strings"
	"testing"
)

func TestPublicMemoryRecordsCannotCarryContentOrExecutionAuthority(t *testing.T) {
	for _, value := range []any{Scope{}, RetentionPolicy{}, Review{}, PutRequest{}, GetRequest{},
		AccessRequest{}, Decision{}, ReviewRequest{}, ReviewDecision{}, Record{}, Result{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"content", "bytes", "prompt", "instruction", "credential",
				"secret", "queryhandle", "query_handle", "path", "uri", "url", "callback", "connector", "executor"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("unsafe public field %s.%s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable public field %s.%s: %v", typeOf.Name(), field.Name, field.Type)
			}
		}
	}
}

func TestMemoryPortsRemainNarrow(t *testing.T) {
	store := reflect.TypeOf((*Store)(nil)).Elem()
	want := map[string]bool{"Namespace": true, "Load": true, "Recover": true, "Commit": true}
	if store.NumMethod() != len(want) {
		t.Fatalf("store methods=%d", store.NumMethod())
	}
	for index := 0; index < store.NumMethod(); index++ {
		if !want[store.Method(index).Name] {
			t.Fatalf("unexpected store method %s", store.Method(index).Name)
		}
	}
	authority := reflect.TypeOf((*Authority)(nil)).Elem()
	review := reflect.TypeOf((*ReviewAuthority)(nil)).Elem()
	if authority.NumMethod() != 1 || authority.Method(0).Name != "AuthorizeMemory" || review.NumMethod() != 1 || review.Method(0).Name != "AuthorizeReview" {
		t.Fatalf("authority=%v review=%v", authority, review)
	}
}
