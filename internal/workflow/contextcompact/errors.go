package contextcompact

import "errors"

type Code string

const (
	InvalidInput Code = "invalid_input"
	Denied       Code = "denied"
	Conflict     Code = "conflict"
	Canceled     Code = "canceled"
	Timeout      Code = "timeout"
	Unavailable  Code = "unavailable"
	Internal     Code = "internal"
)

type Error struct {
	code      Code
	reason    string
	retryable bool
	cause     error
}

func (value *Error) Error() string {
	return "context compaction " + string(value.code) + ": " + value.reason
}
func (value *Error) Unwrap() error { return value.cause }

func newError(code Code, reason string, retryable bool, cause error) error {
	return &Error{code: code, reason: reason, retryable: retryable, cause: cause}
}

func ErrorCode(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return Unavailable
}

func ErrorReason(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.reason
	}
	return "compaction_dependency_unavailable"
}

func Retryable(err error) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.retryable
}
