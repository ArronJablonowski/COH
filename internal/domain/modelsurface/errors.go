package modelsurface

import "fmt"

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Unsupported  ErrorCode = "unsupported"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
)

type Error struct {
	code   ErrorCode
	reason string
}

func (value *Error) Error() string {
	return fmt.Sprintf("model surface %s: %s", value.code, value.reason)
}

func newError(code ErrorCode, reason string) error { return &Error{code: code, reason: reason} }

func Code(err error) ErrorCode {
	if value, ok := err.(*Error); ok {
		return value.code
	}
	return ""
}

func Reason(err error) string {
	if value, ok := err.(*Error); ok {
		return value.reason
	}
	return ""
}
