package remoteworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

type activeJob struct {
	broker *Broker
	id     string
	scope  workerScope
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

type workerScope struct{ organizationID, tenantID, caseID string }

type jobControlRun struct {
	done     chan struct{}
	evidence string
	err      error
}

type RemoteJobControl struct {
	broker *Broker
	mu     sync.Mutex
	runs   map[string]*jobControlRun
}

type CooperativeControl struct {
	broker *Broker
	mu     sync.Mutex
	runs   map[string]*jobControlRun
}

func NewRemoteJobControl(broker *Broker) (*RemoteJobControl, error) {
	if broker == nil {
		return nil, brokerError(workercontract.InvalidInput, "remote_job_control_configuration_invalid")
	}
	return &RemoteJobControl{broker: broker, runs: make(map[string]*jobControlRun)}, nil
}

func NewCooperativeControl(broker *Broker) (*CooperativeControl, error) {
	if broker == nil {
		return nil, brokerError(workercontract.InvalidInput, "cooperative_control_configuration_invalid")
	}
	return &CooperativeControl{broker: broker, runs: make(map[string]*jobControlRun)}, nil
}

func (*RemoteJobControl) ID() string     { return "remote-worker-jobs" }
func (*RemoteJobControl) Kind() string   { return "remote_job" }
func (*CooperativeControl) ID() string   { return "remote-worker-cooperative" }
func (*CooperativeControl) Kind() string { return "cooperative" }

func (control *RemoteJobControl) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	return runJobControl(ctx, request, &control.mu, control.runs, func() (string, error) {
		jobs := control.broker.jobsFor(request.Scope)
		ids := make([]string, 0, len(jobs))
		for _, job := range jobs {
			ids = append(ids, job.id)
			job.cancel()
		}
		sort.Strings(ids)
		return jobEvidence(request, ids), nil
	})
}

func (control *CooperativeControl) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	return runJobControl(ctx, request, &control.mu, control.runs, func() (string, error) {
		jobs := control.broker.jobsFor(request.Scope)
		ids := make([]string, 0, len(jobs))
		for _, job := range jobs {
			ids = append(ids, job.id)
			job.cancel()
		}
		for _, job := range jobs {
			select {
			case <-job.done:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		sort.Strings(ids)
		return jobEvidence(request, ids), nil
	})
}

func runJobControl(ctx context.Context, request stopcontract.ControlRequest, mu *sync.Mutex,
	runs map[string]*jobControlRun, apply func() (string, error)) (string, error) {
	if request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", brokerError(workercontract.InvalidInput, "job_control_request_invalid")
	}
	key := jobRunKey(request)
	mu.Lock()
	if existing := runs[key]; existing != nil {
		mu.Unlock()
		select {
		case <-existing.done:
			return existing.evidence, existing.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	run := &jobControlRun{done: make(chan struct{})}
	runs[key] = run
	mu.Unlock()
	run.evidence, run.err = apply()
	close(run.done)
	return run.evidence, run.err
}

func (broker *Broker) registerJob(record LeaseRecord, cancel context.CancelFunc) *activeJob {
	scope := record.Request.Scope
	job := &activeJob{broker: broker, id: record.LeaseID,
		scope:  workerScope{organizationID: scope.OrganizationID, tenantID: scope.TenantID, caseID: scope.CaseID},
		cancel: cancel, done: make(chan struct{})}
	broker.jobsMu.Lock()
	broker.jobs[job.id] = job
	broker.jobsMu.Unlock()
	return job
}

func (job *activeJob) finish() {
	job.once.Do(func() {
		job.broker.jobsMu.Lock()
		if job.broker.jobs[job.id] == job {
			delete(job.broker.jobs, job.id)
		}
		job.broker.jobsMu.Unlock()
		close(job.done)
	})
}

func (broker *Broker) jobsFor(scope stopcontract.Scope) []*activeJob {
	broker.jobsMu.Lock()
	defer broker.jobsMu.Unlock()
	jobs := make([]*activeJob, 0)
	for _, job := range broker.jobs {
		if job.scope.organizationID == scope.OrganizationID && job.scope.tenantID == scope.TenantID &&
			(scope.Kind == "global" || job.scope.caseID == scope.CaseID) {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func jobRunKey(request stopcontract.ControlRequest) string {
	scope := request.Scope
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID +
		"\x00" + strconv.FormatUint(request.Epoch, 10)
}

func jobEvidence(request stopcontract.ControlRequest, ids []string) string {
	value, _ := json.Marshal(struct {
		Scope stopcontract.Scope
		Epoch uint64
		Jobs  []string
	}{Scope: request.Scope, Epoch: request.Epoch, Jobs: ids})
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
