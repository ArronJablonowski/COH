package queryevidence

import (
	"context"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

// RuntimeRecorder owns one prepared query attempt. The runtime's revision-one
// callback creates evidence genesis with the exact native-query stream; later
// callbacks append normal immutable transitions.
type RuntimeRecorder struct {
	mu         sync.Mutex
	controller *Controller
	start      StartCommand
	source     Source
	started    bool
}

func NewRuntimeRecorder(controller *Controller, start StartCommand, source Source) (*RuntimeRecorder, error) {
	if controller == nil || source == nil || start.RuntimeSession != (queryruntime.Session{}) {
		return nil, newError(InvalidInput, "runtime_recorder_configuration_invalid", nil)
	}
	return &RuntimeRecorder{controller: controller, start: start, source: source}, nil
}

func (recorder *RuntimeRecorder) RecordQuerySession(ctx context.Context, session queryruntime.Session) error {
	if recorder == nil || recorder.controller == nil {
		return newError(InvalidInput, "runtime_recorder_required", nil)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if session.Revision == 1 {
		if recorder.started {
			return newError(Conflict, "runtime_genesis_changed", nil)
		}
		command := recorder.start
		command.RuntimeSession = session
		if _, err := recorder.controller.Start(ctx, command, recorder.source); err != nil {
			return err
		}
		recorder.started = true
		recorder.source = nil
		return nil
	}
	if !recorder.started {
		return newError(Conflict, "runtime_genesis_missing", nil)
	}
	return recorder.controller.RecordQuerySession(ctx, session)
}

var _ queryruntime.Recorder = (*RuntimeRecorder)(nil)
