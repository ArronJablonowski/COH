package broker

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/connector"
	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func TestToolRouteConnectorCapabilityAndConstructorRemainBrokerPrivate(t *testing.T) {
	typeOfAuthority := reflect.TypeOf(toolRouteAuthority{})
	connectorType := reflect.TypeOf((*connector.Gateway)(nil)).Elem()
	foundConnector := false
	for index := 0; index < typeOfAuthority.NumField(); index++ {
		field := typeOfAuthority.Field(index)
		if field.Type == connectorType {
			foundConnector = true
			if field.IsExported() {
				t.Fatalf("connector capability is exported as %s", field.Name)
			}
		}
	}
	if !foundConnector {
		t.Fatal("route authority does not own the sole connector capability")
	}
	authorityType := reflect.TypeOf((*Authority)(nil)).Elem()
	workflowType := reflect.TypeOf((*workflow.ActionAuthority)(nil)).Elem()
	if authorityType.NumMethod() != 1 || !authorityType.Implements(workflowType) {
		t.Fatalf("unexpected public authority surface: %v", authorityType)
	}
	method := authorityType.Method(0)
	want := reflect.TypeOf(func(context.Context, domain.ToolIntent) (domain.ActionReceipt, error) {
		return domain.ActionReceipt{}, nil
	})
	if method.Name != "Submit" || method.Type != want {
		t.Fatalf("unexpected authority method: %s %v", method.Name, method.Type)
	}
}
