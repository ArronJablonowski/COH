package investigationprojection

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInputError ErrorCode = "invalid_input"
	CanceledError     ErrorCode = "canceled"
	TimeoutError      ErrorCode = "timeout"
	DeniedError       ErrorCode = "denied"
	ConflictError     ErrorCode = "conflict"
	UnavailableError  ErrorCode = "unavailable"
)

type Reason string

const (
	InvalidInput          Reason = "invalid_input"
	ScopeMismatch         Reason = "scope_mismatch"
	IntegrityFailure      Reason = "integrity_failure"
	ProjectionDivergent   Reason = "projection_divergent"
	AuthorityDenied       Reason = "authority_denied"
	DependencyUnavailable Reason = "dependency_unavailable"
	ContextCanceled       Reason = "context_canceled"
	ContextDeadline       Reason = "context_deadline"
	IdempotencyConflict   Reason = "idempotency_conflict"
)

type DomainError struct {
	code   ErrorCode
	reason Reason
	cause  error
}

func (err *DomainError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("investigation projection %s: %s", err.code, err.reason)
}

func (err *DomainError) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason Reason, cause error) error {
	return &DomainError{code: code, reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *DomainError
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}

func ErrorReason(err error) Reason {
	var target *DomainError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}
