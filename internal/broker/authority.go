// Package broker is the sole action authority. It rechecks policy immediately
// before dispatch and is the only production boundary allowed to import a
// connector. Workflows depend only on their own ActionAuthority interface.
package broker

import (
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Authority is the action-authority capability visible to composition roots.
// COH-E05 produces only a broker-private pre-dispatch capability. A runtime
// implementation remains withheld until COH-E06 can consume that capability
// immediately at the isolated dispatch boundary; no partial bypass is exposed.
type Authority interface {
	workflow.ActionAuthority
}
