package toolroute

import "errors"

type Code string

const (
	InvalidInput Code = "invalid_input"
	Denied       Code = "denied"
	Internal     Code = "internal"
)

type Error struct {
	Code   Code
	Reason string
	Cause  error
}

func (err *Error) Error() string { return "tool route " + string(err.Code) + ": " + err.Reason }
func (err *Error) Unwrap() error { return err.Cause }

func newError(code Code, reason string, cause error) error {
	return &Error{Code: code, Reason: reason, Cause: cause}
}

func ErrorCode(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return Internal
}

func ErrorReason(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Reason
	}
	return "internal"
}
