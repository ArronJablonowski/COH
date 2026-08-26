package estop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type deadlineProbeControl struct {
	id    string
	kind  string
	mu    sync.Mutex
	seen  time.Duration
	block bool
}

func (control *deadlineProbeControl) ID() string   { return control.id }
func (control *deadlineProbeControl) Kind() string { return control.kind }
func (control *deadlineProbeControl) Apply(ctx context.Context, _ stopcontract.ControlRequest) (string, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return "", errors.New("deadline missing")
	}
	control.mu.Lock()
	control.seen = time.Until(deadline)
	control.mu.Unlock()
	if control.block {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return digest("timing-" + control.id), nil
}

func (control *deadlineProbeControl) budget() time.Duration {
	control.mu.Lock()
	defer control.mu.Unlock()
	return control.seen
}

func TestTimingConformancePublishesAndAppliesAllObjectives(t *testing.T) {
	controls := timingControls(false)
	controller := timingController(t, controls)
	command, authority := fixture(false)
	result, _, err := controller.Activate(context.Background(), command, authority)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]time.Duration{
		"credential":  stopcontract.LeaseRejectObjective,
		"egress":      stopcontract.EgressCutObjective,
		"remote_job":  stopcontract.WorkflowSignalObjective,
		"workflow":    stopcontract.WorkflowSignalObjective,
		"cooperative": stopcontract.TerminationObjective,
	}
	if len(result.Acknowledgements) != len(want) {
		t.Fatalf("acknowledgements=%d", len(result.Acknowledgements))
	}
	for _, acknowledgement := range result.Acknowledgements {
		objective := want[acknowledgement.ControlKind]
		if acknowledgement.Outcome != "applied" || acknowledgement.ObjectiveNanos != objective.Nanoseconds() ||
			acknowledgement.ElapsedNanos >= acknowledgement.ObjectiveNanos {
			t.Fatalf("acknowledgement=%+v objective=%v", acknowledgement, objective)
		}
	}
	for _, control := range controls {
		objective := want[control.kind]
		budget := control.budget()
		if budget <= objective-250*time.Millisecond || budget > objective {
			t.Fatalf("control=%s budget=%v objective=%v", control.id, budget, objective)
		}
	}
}

func TestTimingConformanceEnforcesLeaseDeadlineWithMonotonicElapsedTime(t *testing.T) {
	controls := timingControls(true)
	controller := timingController(t, controls)
	command, authority := fixture(false)
	started := time.Now()
	result, _, err := controller.Activate(context.Background(), command, authority)
	elapsed := time.Since(started)
	if stopcontract.Reason(err) != "containment_incomplete" || elapsed < 900*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatalf("elapsed=%v result=%+v err=%v", elapsed, result, err)
	}
	found := false
	for _, acknowledgement := range result.Acknowledgements {
		if acknowledgement.ControlKind == "credential" {
			found = true
			if acknowledgement.Outcome != "timeout" || acknowledgement.ReasonCode != "control_timeout" ||
				acknowledgement.ObjectiveNanos != time.Second.Nanoseconds() || acknowledgement.ElapsedNanos < 900*time.Millisecond.Nanoseconds() {
				t.Fatalf("credential acknowledgement=%+v", acknowledgement)
			}
		}
	}
	if !found {
		t.Fatal("credential acknowledgement missing")
	}
}

func timingControls(blockCredential bool) []*deadlineProbeControl {
	return []*deadlineProbeControl{
		{id: "credential-timing", kind: "credential", block: blockCredential},
		{id: "egress-timing", kind: "egress"},
		{id: "remote-job-timing", kind: "remote_job"},
		{id: "workflow-timing", kind: "workflow"},
		{id: "cooperative-timing", kind: "cooperative"},
	}
}

func timingController(t *testing.T, controls []*deadlineProbeControl) *Controller {
	t.Helper()
	ports := make([]Control, len(controls))
	for index := range controls {
		ports[index] = controls[index]
	}
	controller, err := NewWithDependencies(NewMemoryStore(), &fakeAudit{},
		&fixedClock{now: time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)}, ports...)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
