// Package broker is the sole action authority. It rechecks policy immediately
// before dispatch and is the only production boundary allowed to import a
// connector. Workflows depend only on their own ActionAuthority interface.
package broker

import (
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Authority is the only action capability visible to workflow composition.
// The CYB-69 implementation remains broker-private: it resolves trusted route
// context, rechecks pre-dispatch authority and E-stop state, persists an
// audited dispatch boundary, and only then invokes the private connector.
type Authority interface {
	workflow.ActionAuthority
}
