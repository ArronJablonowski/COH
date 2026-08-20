package architecture

import "fmt"

// ErrorCode is a stable machine-readable contract-check failure class.
type ErrorCode string

const (
	CodeInvalidInput       ErrorCode = "invalid_input"
	CodeUnsupportedVersion ErrorCode = "unsupported_version"
	CodeDenied             ErrorCode = "dependency_denied"
	CodeCanceled           ErrorCode = "canceled"
	CodeToolFailure        ErrorCode = "tool_failure"
)

// ContractError carries safe details suitable for CI output. It never embeds
// file contents, environment variables, or command output that may be secret.
type ContractError struct {
	Code   ErrorCode
	Field  string
	Detail string
	Cause  error
}

func (e *ContractError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
	return fmt.Sprintf("%s at %s: %s", e.Code, e.Field, e.Detail)
}

func (e *ContractError) Unwrap() error { return e.Cause }

func contractError(code ErrorCode, field, detail string, cause error) error {
	return &ContractError{Code: code, Field: field, Detail: detail, Cause: cause}
}
