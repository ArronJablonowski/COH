package providercontract

import "time"

// StreamValidator enforces correlation, contiguous ordering, monotonic
// observation time, and a single terminal event for one inference attempt.
type StreamValidator struct {
	requestID  string
	attemptID  string
	next       uint64
	last       time.Time
	started    bool
	terminated bool
}

func (validator *StreamValidator) Apply(event ValidatedStreamEvent) error {
	if validator == nil || event.Digest() == "" {
		return NewError(InvalidInput, "stream_validator")
	}
	value := event.Value()
	if validator.terminated {
		return NewError(Conflict, "stream_after_terminal")
	}
	if !validator.started {
		if value.Sequence != 0 {
			return NewError(Conflict, "stream_sequence")
		}
		validator.requestID, validator.attemptID, validator.started = value.RequestID, value.AttemptID, true
	} else if value.RequestID != validator.requestID || value.AttemptID != validator.attemptID || value.Sequence != validator.next {
		return NewError(Conflict, "stream_sequence")
	}
	observed, _ := parseTimestamp(value.ObservedAt)
	if !validator.last.IsZero() && observed.Before(validator.last) {
		return NewError(Conflict, "stream_time_regression")
	}
	validator.last = observed
	validator.next = value.Sequence + 1
	validator.terminated = value.Kind == "completed" || value.Kind == "error"
	return nil
}

func (validator *StreamValidator) Complete() bool {
	return validator != nil && validator.started && validator.terminated
}
