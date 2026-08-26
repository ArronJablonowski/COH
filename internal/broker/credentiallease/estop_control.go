package credentiallease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const emergencyStopControlID = "credential-leases"

// EmergencyStopControl revokes every credential capability in an activated
// global or case scope. Repeated application is idempotent and returns the
// same evidence while the stopped scope cannot issue new leases.
type EmergencyStopControl struct{ store Store }

func NewEmergencyStopControl(store Store) (*EmergencyStopControl, error) {
	if store == nil {
		return nil, brokerError(leasecontract.InvalidInput, "stop_control_configuration_invalid")
	}
	return &EmergencyStopControl{store: store}, nil
}

func (*EmergencyStopControl) ID() string   { return emergencyStopControlID }
func (*EmergencyStopControl) Kind() string { return "credential" }

func (control *EmergencyStopControl) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	if control == nil || control.store == nil || request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", brokerError(leasecontract.InvalidInput, "stop_control_request_invalid")
	}
	count, err := control.store.RevokeScope(ctx, request.Scope.OrganizationID, request.Scope.TenantID,
		request.Scope.CaseID, "emergency_stop")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", scopeKey(request.Scope), request.Epoch, count)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func scopeKey(scope stopcontract.Scope) string {
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID
}
