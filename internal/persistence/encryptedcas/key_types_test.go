package encryptedcas

import (
	"reflect"
	"testing"
)

func TestKeyManagerRemainsAdapterLocalAndNarrow(t *testing.T) {
	port := reflect.TypeOf((*KeyManager)(nil)).Elem()
	want := []string{"GenerateDataKey", "UnwrapDataKey"}
	if port.NumMethod() != len(want) {
		t.Fatalf("key-manager methods=%d", port.NumMethod())
	}
	for index, name := range want {
		if port.Method(index).Name != name {
			t.Fatalf("key-manager method[%d]=%s", index, port.Method(index).Name)
		}
	}
	if DataKeyBytes != 32 {
		t.Fatalf("AES-256 key bytes=%d", DataKeyBytes)
	}
}
