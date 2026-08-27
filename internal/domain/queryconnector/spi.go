package queryconnector

import "context"

// Connector is deliberately narrower than HTTP or a vendor SDK. Every method
// is read-only, bounded, authority-bound, and returns a typed lifecycle record.
type Connector interface {
	Probe(context.Context, Scope, AuthorityBinding) (CapabilitySnapshot, error)
	DiscoverSchema(context.Context, SchemaRequest) (SchemaPage, error)
	Validate(context.Context, Query) (ValidationResult, error)
	Execute(context.Context, Query, ValidationResult) (Execution, error)
	Poll(context.Context, PollRequest) (PollResult, error)
	NextPage(context.Context, PageRequest) (ResultPage, error)
	Cancel(context.Context, CancelRequest) (Cancellation, error)
}
