package evidencecatalog

import (
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestCatalogImplementsNarrowEvidenceResolverAndRequiresDependencies(t *testing.T) {
	port := reflect.TypeOf((*evidencelifecycle.EvidenceResolver)(nil)).Elem()
	implementation := reflect.TypeOf((*Catalog)(nil))
	if !implementation.Implements(port) || port.NumMethod() != 1 ||
		port.Method(0).Name != "ResolveEvidenceSet" {
		t.Fatal("catalog does not implement the narrow evidence resolver port")
	}
	if _, err := New(nil, nil, nil); evidencelifecycle.CodeOf(err) != evidencelifecycle.InvalidInput {
		t.Fatalf("nil dependencies err=%v", err)
	}
}
