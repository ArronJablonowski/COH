package openairesponses

import (
	"context"
	"errors"
	"fmt"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type Error struct {
	Code      providercontract.ErrorCode
	Reason    string
	Retryable bool
}

func (value *Error) Error() string {
	return fmt.Sprintf("openai responses adapter %s: %s", value.Code, value.Reason)
}

func newError(code providercontract.ErrorCode, reason string, retryable bool) error {
	return &Error{Code: code, Reason: reason, Retryable: retryable}
}

func Code(err error) providercontract.ErrorCode {
	var adapterError *Error
	if errors.As(err, &adapterError) {
		return adapterError.Code
	}
	if errors.Is(err, context.Canceled) {
		return providercontract.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return providercontract.Timeout
	}
	return providercontract.Unavailable
}

func Reason(err error) string {
	var adapterError *Error
	if errors.As(err, &adapterError) {
		return adapterError.Reason
	}
	return "openai_transport_unavailable"
}

func Retryable(err error) bool {
	var adapterError *Error
	return errors.As(err, &adapterError) && adapterError.Retryable
}
