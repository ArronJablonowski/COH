package queryconnector

import "context"

// Connector is deliberately narrower than HTTP or a vendor SDK. Every method
// is read-only, bounded, authority-bound, and returns a typed lifecycle record.
type Connector interface {
	Probe(context.Context, Scope, AuthorityBinding) (ValidatedCapability, error)
	DiscoverSchema(context.Context, SchemaRequest) (ValidatedSchemaPage, error)
	Validate(context.Context, ValidatedQuery) (ValidatedValidation, error)
	Execute(context.Context, ValidatedQuery, ValidatedValidation) (ValidatedExecution, error)
	Poll(context.Context, PollRequest) (ValidatedPoll, error)
	NextPage(context.Context, PageRequest) (ValidatedPage, error)
	Cancel(context.Context, CancelRequest) (ValidatedCancellation, error)
}

// AdmitExecution binds a validator decision to the exact canonical query. It
// prevents a denied, stale, or substituted validation result from reaching an
// adapter's Execute method.
func AdmitExecution(ctx context.Context, query ValidatedQuery, validation ValidatedValidation) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	queryValue, validationValue := query.Value(), validation.Value()
	if query.Digest() == "" || validation.Digest() == "" || validationValue.Outcome != "accepted" {
		return NewError(Denied, "validation_not_accepted", nil)
	}
	if validationValue.QueryID != queryValue.QueryID || validationValue.CanonicalQueryDigest != query.Digest() {
		return NewError(Conflict, "validation_query_mismatch", nil)
	}
	return nil
}
