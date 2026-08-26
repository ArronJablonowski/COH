// Package temporaladapter implements the durable workflow engine with Temporal.
package temporaladapter

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	workflowVersion = "v1"
	querySnapshot   = "coh.snapshot.v1"
	signalLifecycle = "coh.signal.v1"
)

var taskQueuePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type temporalClient interface {
	ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error)
	SignalWorkflow(context.Context, string, string, string, interface{}) error
	QueryWorkflow(context.Context, string, string, string, ...interface{}) (converter.EncodedValue, error)
	CancelWorkflow(context.Context, string, string) error
}

type RetainedHistory struct {
	Definition string
	Version    string
	Digest     string
	JSON       []byte
}

type Config struct {
	TaskQueue        string
	ExecutionTimeout time.Duration
	Histories        map[string]RetainedHistory
}

type Adapter struct {
	mu               sync.Mutex
	client           temporalClient
	taskQueue        string
	executionTimeout time.Duration
	histories        map[string]RetainedHistory
}

func New(backend temporalClient, config Config) (*Adapter, error) {
	if backend == nil {
		return nil, engineError(core.EngineInvalidInput, "new", "client", "Temporal client is required")
	}
	if !taskQueuePattern.MatchString(config.TaskQueue) {
		return nil, engineError(core.EngineInvalidInput, "new", "task_queue", "bounded task queue is required")
	}
	if config.ExecutionTimeout == 0 {
		config.ExecutionTimeout = 24 * time.Hour
	}
	if config.ExecutionTimeout < time.Minute || config.ExecutionTimeout > 365*24*time.Hour {
		return nil, engineError(core.EngineInvalidInput, "new", "execution_timeout", "execution timeout is outside bounds")
	}
	histories := make(map[string]RetainedHistory, len(config.Histories))
	for id, history := range config.Histories {
		if !taskQueuePattern.MatchString(id) || history.Definition != core.OperationWorkflowV1 && history.Definition != core.AgentLoopWorkflowV1 || history.Version != workflowVersion || !validDigest(history.Digest) || len(history.JSON) == 0 {
			return nil, engineError(core.EngineInvalidInput, "new", "histories", "retained history registration is invalid")
		}
		copyHistory := history
		copyHistory.JSON = append([]byte(nil), history.JSON...)
		if digestBytes(copyHistory.JSON) != copyHistory.Digest {
			return nil, engineError(core.EngineDenied, "new", "histories", "retained history digest does not match")
		}
		histories[id] = copyHistory
	}
	return &Adapter{client: backend, taskQueue: config.TaskQueue, executionTimeout: config.ExecutionTimeout, histories: histories}, nil
}

func (adapter *Adapter) String() string {
	return fmt.Sprintf("TemporalAdapter(task_queue=%s)", adapter.taskQueue)
}

var _ core.EngineDriver = (*Adapter)(nil)
var _ temporalClient = (client.Client)(nil)
