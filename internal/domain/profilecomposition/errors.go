package profilecomposition

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
	return "profile composition " + string(err.code) + ": " + err.reason
}
func newError(code ErrorCode, reason string) error { return &Error{code: code, reason: reason} }

// NewError creates a fixed-code redacted error for trusted boundary adapters.
// Callers must use stable non-sensitive reason codes.
func NewError(code ErrorCode, reason string) error { return newError(code, reason) }

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
