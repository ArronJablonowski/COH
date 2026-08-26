package remoteworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

const emergencyStopControlID = "runner-leases"

// EmergencyStopControl revokes every outstanding runner capability in an
// activated global or case scope.
type EmergencyStopControl struct{ store Store }

func NewEmergencyStopControl(store Store) (*EmergencyStopControl, error) {
	if store == nil {
		return nil, brokerError(workercontract.InvalidInput, "stop_control_configuration_invalid")
	}
	return &EmergencyStopControl{store: store}, nil
}

func (*EmergencyStopControl) ID() string   { return emergencyStopControlID }
func (*EmergencyStopControl) Kind() string { return "credential" }

func (control *EmergencyStopControl) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	if control == nil || control.store == nil || request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", brokerError(workercontract.InvalidInput, "stop_control_request_invalid")
	}
	count, err := control.store.RevokeLeaseScope(ctx, request.Scope.OrganizationID, request.Scope.TenantID,
		request.Scope.CaseID, "emergency_stop")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", stopScopeKey(request.Scope), request.Epoch, count)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func stopScopeKey(scope stopcontract.Scope) string {
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID
}
