package securityonion

import "github.com/ArronJablonowski/COH/internal/domain/queryconnector"

func invalid(reason string) error {
	return queryconnector.NewError(queryconnector.InvalidInput, reason, nil)
}

func denied(reason string) error {
	return queryconnector.NewError(queryconnector.Denied, reason, nil)
}

func conflict(reason string) error {
	return queryconnector.NewError(queryconnector.Conflict, reason, nil)
}
