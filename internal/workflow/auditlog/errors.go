package auditlog

import "errors"

var (
	ErrInvalidInput = errors.New("audit log invalid input")
	ErrConflict     = errors.New("audit log conflict")
	ErrUnavailable  = errors.New("audit log unavailable")
	ErrIntegrity    = errors.New("audit log integrity failure")
)
