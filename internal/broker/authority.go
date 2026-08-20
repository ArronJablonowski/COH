// Package broker is the sole action authority. It rechecks policy immediately
// before dispatch and is the only production boundary allowed to import a
// connector. Workflows depend only on their own ActionAuthority interface.
package broker

import (
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Authority is the action-authority capability visible to composition roots.
// Runtime implementations arrive only with the policy, approval, audit, and
// dispatch controls in COH-E05; this package does not provide a partial bypass.
type Authority interface {
	workflow.ActionAuthority
}
