package mappingregistry

import (
	"reflect"
	"strings"
	"testing"
)

func TestNarrowPortsExposeNoUnsafeSurface(t *testing.T) {
	for _, value := range []any{Dependencies{}, SourceBinding{}, SignatureRequest{}, Command{}, Commit{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := strings.ToLower(typeOf.Field(index).Name)
			for _, forbidden := range []string{"path", "url", "sql", "http", "client", "connector", "executor", "credential", "secret", "shell", "callback", "privatekey", "publickey", "evidencebytes", "policysource"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s exposes forbidden field %s", typeOf.Name(), typeOf.Field(index).Name)
				}
			}
		}
	}
	ports := []any{(*EvidenceVerifier)(nil), (*SignatureVerifier)(nil), (*SourceSchemaResolver)(nil), (*RegistryStore)(nil), (*AuditBuilder)(nil), (*ProvenanceBuilder)(nil), (*Clock)(nil)}
	for _, port := range ports {
		typeOf := reflect.TypeOf(port).Elem()
		if typeOf.NumMethod() == 0 || typeOf.NumMethod() > 6 {
			t.Fatalf("%s method count=%d", typeOf.Name(), typeOf.NumMethod())
		}
	}
}
