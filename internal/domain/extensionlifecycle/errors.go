package extensionlifecycle

import "errors"

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unsupported  ErrorCode = "unsupported"
)

type Error struct {
	code   ErrorCode
	reason string
}

func (err *Error) Error() string {
	return "extension lifecycle " + string(err.code) + ": " + err.reason
}
func newError(code ErrorCode, reason string) error { return &Error{code: code, reason: reason} }
func Code(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return ""
}
func Reason(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.reason
	}
	return ""
}
