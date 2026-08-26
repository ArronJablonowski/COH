package remoteworker

import (
	"reflect"
	"strings"
	"testing"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestCapabilityAndSecretSurfaceIsPrivate(t *testing.T) {
	handleType := reflect.TypeOf(Handle{})
	for index := 0; index < handleType.NumField(); index++ {
		field := handleType.Field(index)
		if field.IsExported() && field.Name != "LeaseID" {
			t.Fatalf("unexpected exported handle field: %s", field.Name)
		}
	}
	for _, contract := range []any{
		workercontract.EnrollmentRequest{}, workercontract.LeaseRequest{}, workercontract.DispatchRequest{},
		workercontract.RevocationRequest{}, workercontract.Decision{}, workercontract.DispatchEnvelope{},
	} {
		typ := reflect.TypeOf(contract)
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"lease_token", "private_key", "secret_value", "capability_bytes"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s exposes forbidden field %s", typ.Name(), field.Name)
				}
			}
		}
	}
}
