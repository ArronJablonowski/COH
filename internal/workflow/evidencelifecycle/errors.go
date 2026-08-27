package evidencelifecycle

import "errors"

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	NotFound     ErrorCode = "not_found"
	Conflict     ErrorCode = "conflict"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
)

type Error struct {
	Code      ErrorCode
	Reason    string
	Retryable bool
	cause     error
}

func (value *Error) Error() string {
	if value == nil {
		return ""
	}
	return string(value.Code) + ": " + value.Reason
}

func (value *Error) Unwrap() error {
	if value == nil {
		return nil
	}
	return value.cause
}

func newError(code ErrorCode, reason string, retryable bool, cause error) error {
	return &Error{Code: code, Reason: reason, Retryable: retryable, cause: cause}
}

func CodeOf(err error) ErrorCode {
	var value *Error
	if errors.As(err, &value) {
		return value.Code
	}
	return Unavailable
}

func Reason(err error) string {
	var value *Error
	if errors.As(err, &value) {
		return value.Reason
	}
	return "dependency_unavailable"
}

func Retryable(err error) bool {
	var value *Error
	return errors.As(err, &value) && value.Retryable
}
