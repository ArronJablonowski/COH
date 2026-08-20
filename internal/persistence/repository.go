// Package persistence contains metadata and artifact-store adapters.
package persistence

import "github.com/ArronJablonowski/COH/internal/workflow"

// Repository marks a persistence implementation of the workflow port.
type Repository interface {
	workflow.Repository
}
