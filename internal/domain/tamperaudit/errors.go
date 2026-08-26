package tamperaudit

import "errors"

var (
	ErrInvalidInput       = errors.New("tamper audit invalid input")
	ErrUnsupportedVersion = errors.New("tamper audit unsupported version")
	ErrIntegrity          = errors.New("tamper audit integrity failure")
)
