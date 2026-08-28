package profileactivation

import "errors"

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Conflict     ErrorCode = "conflict"
	Unavailable  ErrorCode = "unavailable"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
)

type Error struct {
	code   ErrorCode
	reason string
}

func (err *Error) Error() string                   { return "profile activation " + string(err.code) + ": " + err.reason }
func newError(code ErrorCode, reason string) error { return &Error{code: code, reason: reason} }

// NewInvalidInput returns a fixed redacted boundary error.
func NewInvalidInput(reason string) error { return newError(InvalidInput, reason) }

// NewDenied returns a fixed redacted denial.
func NewDenied(reason string) error { return newError(Denied, reason) }

// NewCanceled returns a fixed redacted cancellation error.
func NewCanceled(reason string) error { return newError(Canceled, reason) }

// NewTimeout returns a fixed redacted timeout error.
func NewTimeout(reason string) error { return newError(Timeout, reason) }

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
