package broker

import (
	"context"
	"errors"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
)

type toolRouteCode string

const (
	routeCodeInvalidInput toolRouteCode = "invalid_input"
	routeCodeDenied       toolRouteCode = "denied"
	routeCodeCanceled     toolRouteCode = "canceled"
	routeCodeTimeout      toolRouteCode = "timeout"
	routeCodeUnavailable  toolRouteCode = "unavailable"
	routeCodeUncertain    toolRouteCode = "uncertain"
)

type toolRouteError struct {
	code          toolRouteCode
	reason        string
	indeterminate bool
	cause         error
}

func (err *toolRouteError) Error() string {
	return "tool route " + string(err.code) + ": " + err.reason
}
func (err *toolRouteError) Unwrap() error               { return err.cause }
func (err *toolRouteError) ActivityOutcome() string     { return string(err.code) }
func (err *toolRouteError) DispatchIndeterminate() bool { return err.indeterminate }

func newRouteError(code toolRouteCode, reason string, indeterminate bool, cause error) error {
	return &toolRouteError{code: code, reason: reason, indeterminate: indeterminate, cause: cause}
}

func routeCode(err error) toolRouteCode {
	var typed *toolRouteError
	if errors.As(err, &typed) {
		return typed.code
	}
	return routeCodeUnavailable
}

func routeReason(err error) string {
	var typed *toolRouteError
	if errors.As(err, &typed) {
		return typed.reason
	}
	return "route_dependency_unavailable"
}

func mapRouteContext(ctx context.Context, reason string, indeterminate bool, err error) error {
	if errors.Is(err, context.Canceled) || ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newRouteError(routeCodeCanceled, reason, indeterminate, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newRouteError(routeCodeTimeout, reason, indeterminate, context.DeadlineExceeded)
	}
	return newRouteError(mapLifecycleCode(err), lifecycle.Reason(err), indeterminate, nil)
}

func mapLifecycleCode(err error) toolRouteCode {
	switch lifecycle.Code(err) {
	case lifecycle.InvalidInput:
		return routeCodeInvalidInput
	case lifecycle.Denied:
		return routeCodeDenied
	case lifecycle.Canceled:
		return routeCodeCanceled
	case lifecycle.Timeout:
		return routeCodeTimeout
	default:
		return routeCodeUnavailable
	}
}
