package ociexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

type attempt struct {
	fingerprint string
	done        chan struct{}
	result      Result
	err         error
}

type Executor struct {
	resolver      Resolver
	authorizer    Authorizer
	network       *ContainmentNetworkBroker
	runtime       Runtime
	clock         Clock
	registrations map[string]Registration
	mu            sync.Mutex
	attempts      map[string]*attempt
}

func New(resolver Resolver, authorizer Authorizer, network *ContainmentNetworkBroker, runtime Runtime, clock Clock,
	registrations []Registration) (*Executor, error) {
	if resolver == nil || authorizer == nil || network == nil || runtime == nil || clock == nil ||
		len(registrations) == 0 || len(registrations) > MaximumRegistrations {
		return nil, NewError(InvalidInput, "executor_dependencies")
	}
	values := make(map[string]Registration, len(registrations))
	for _, registration := range registrations {
		if err := validateRegistration(registration); err != nil {
			return nil, err
		}
		key := registrationKey(registration.Tool, registration.Operation)
		if _, duplicate := values[key]; duplicate {
			return nil, NewError(Conflict, "registration_duplicate")
		}
		values[key] = cloneRegistration(registration)
	}
	return &Executor{resolver: resolver, authorizer: authorizer, network: network, runtime: runtime, clock: clock,
		registrations: values, attempts: make(map[string]*attempt)}, nil
}

func (executor *Executor) Execute(ctx context.Context, request Request) (Result, error) {
	if executor == nil || executor.resolver == nil || executor.authorizer == nil || executor.network == nil ||
		executor.runtime == nil || executor.clock == nil {
		return Result{}, NewError(Unavailable, "executor_unavailable")
	}
	if err := validateRequest(ctx, request); err != nil {
		return Result{}, err
	}
	fingerprint, err := requestFingerprint(request)
	if err != nil {
		return Result{}, err
	}
	current, owner, err := executor.reserve(ctx, request.AttemptID, fingerprint)
	if err != nil {
		return Result{}, err
	}
	if !owner {
		return replayAttempt(ctx, current)
	}
	result, executionErr := executor.executeOwned(ctx, request)
	executor.finish(current, result, executionErr)
	return cloneResult(result), executionErr
}

func (executor *Executor) executeOwned(ctx context.Context, request Request) (Result, error) {
	boundaryCtx, cancelBoundary := context.WithTimeout(ctx, 5*time.Minute)
	defer cancelBoundary()
	started := executor.clock.Now().UTC()
	base := Provenance{AttemptID: request.AttemptID, OrganizationID: request.OrganizationID,
		TenantID: request.TenantID, CaseID: request.CaseID, ActorID: request.ActorID, Tool: request.Tool,
		Operation: request.Operation, RequiredTier: request.RequiredTier, ImageReferenceDigest: request.Tool.ArtifactDigest,
		StartedAt: formatTime(started), Outcome: "denied", ExitCode: -1}
	if started.IsZero() {
		return terminal(base, executor.clock.Now(), Unavailable, "clock_unavailable", RuntimeResult{})
	}
	rawInputDigest, err := inputRequestDigest(request.Inputs)
	if err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	authorizationRequest := AuthorizationRequest{AttemptID: request.AttemptID, OrganizationID: request.OrganizationID,
		TenantID: request.TenantID, CaseID: request.CaseID, ActorID: request.ActorID, Tool: request.Tool,
		Operation: request.Operation, RequiredTier: request.RequiredTier, InputDigest: rawInputDigest}
	authority, err := executor.authorizer.Authorize(boundaryCtx, authorizationRequest)
	if err != nil {
		mapped := mapBoundaryError(err, "authorization_unavailable")
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), RuntimeResult{})
	}
	if err := validateDispatchAuthority(authority, authorizationRequest, executor.clock.Now().UTC()); err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	base.AuthorizationID, base.PolicyDecisionDigest = authority.AuthorizationID, authority.DecisionDigest
	capability, err := executor.resolver.ResolveOperation(boundaryCtx, request.Tool, request.Operation,
		request.RequiredTier, authority.RuntimeCeiling, clonePublisherAuthority(request.Publisher))
	if err != nil {
		mapped := mapRegistryError(err)
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), RuntimeResult{})
	}
	if err := validateCapability(request, authority.RuntimeCeiling, capability); err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	base.ManifestDigest, base.ManifestID = capability.ManifestDigest, capability.ManifestID
	base.EffectiveCeiling = capability.EffectiveCeiling
	registration, found := executor.registrations[registrationKey(request.Tool, request.Operation)]
	if !found {
		return terminal(base, executor.clock.Now(), Denied, "image_not_registered", RuntimeResult{})
	}
	if err := validateMountBudget(registration.WritableMounts, capability.Operation.ResourceLimits.EphemeralStorageBytes); err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	input, err := encodeInputs(capability.Operation.InputFields, request.Inputs)
	if err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	environment := cleanEnvironment(registration.FixedEnvironment)
	base.EntrypointDigest = digestBytes([]byte(registration.Entrypoint))
	base.ArgumentDigest = digestBytes(canonicalBytes(registration.FixedArguments))
	base.EnvironmentDigest = digestBytes(canonicalBytes(environment))
	base.InputDigest = digestBytes(input)
	base.MountDigest = digestBytes(canonicalBytes(registration.WritableMounts))
	policy := cloneNetworkPolicy(capability.Operation.NetworkPolicy)
	base.NetworkPolicyDigest = digestBytes(canonicalBytes(policy))
	networkRequest := NetworkRequest{AttemptID: request.AttemptID, OrganizationID: request.OrganizationID,
		TenantID: request.TenantID, CaseID: request.CaseID, ActorID: request.ActorID,
		AuthorizationID: authority.AuthorizationID, AuthorityUntil: authority.ValidUntil, Policy: policy,
		PolicyDigest: base.NetworkPolicyDigest}
	lease, err := executor.network.Acquire(boundaryCtx, cloneNetworkRequest(networkRequest))
	if err != nil {
		mapped := mapBoundaryError(err, "network_broker_unavailable")
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), RuntimeResult{})
	}
	if err := validateNetworkLease(lease, networkRequest, authority, executor.clock.Now().UTC()); err != nil {
		if lease.Cleanup != nil {
			cleanupErr := lease.Cleanup()
			base.CleanupComplete = cleanupErr == nil
			if cleanupErr != nil {
				return terminal(base, executor.clock.Now(), Unavailable, "network_cleanup_failed", RuntimeResult{})
			}
		}
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), RuntimeResult{})
	}
	base.NetworkEnforcementHash = lease.EnforcementDigest
	limits := capability.Operation.ResourceLimits
	plan := ContainerPlan{AttemptID: request.AttemptID,
		ImageReference: registration.ImageRepository + "@" + registration.ImageDigest,
		ImageDigest:    registration.ImageDigest, Entrypoint: registration.Entrypoint,
		Arguments: slices.Clone(registration.FixedArguments), HealthArguments: slices.Clone(registration.HealthArguments),
		Environment: environment, Input: input, RunAsUser: registration.RunAsUser, RunAsGroup: registration.RunAsGroup,
		WorkingDirectory: "/work", WritableMounts: slices.Clone(registration.WritableMounts), Limits: limits,
		Network: cloneNetworkPolicy(policy), EngineNetwork: lease.EngineNetwork,
		NetworkPolicyHash: base.NetworkPolicyDigest}
	expectedSpecDigest := digestBytes(canonicalBytes(plan))
	expectedHealthDigest := digestBytes(canonicalBytes(registration.HealthArguments))
	runCtx, cancel := context.WithTimeout(boundaryCtx, time.Duration(limits.WallTimeMilliseconds)*time.Millisecond)
	runtimeResult, runErr := executor.runtime.Execute(runCtx, plan)
	cancel()
	networkCleanupErr := lease.Cleanup()
	base.CleanupComplete = runtimeResult.CleanupComplete && networkCleanupErr == nil
	if networkCleanupErr != nil || !runtimeResult.CleanupComplete {
		return terminal(base, executor.clock.Now(), Unavailable, "runtime_cleanup_failed", runtimeResult)
	}
	if uint64(len(runtimeResult.StandardOutput))+uint64(len(runtimeResult.StandardError)) > limits.OutputBytes ||
		runtimeResult.ExitCode < -1 || runtimeResult.ContainerSpecDigest != expectedSpecDigest ||
		runtimeResult.HealthCommandDigest != expectedHealthDigest || !digestPattern.MatchString(runtimeResult.RuntimeDigest) ||
		runtimeResult.ResolvedImageDigest != "" && runtimeResult.ResolvedImageDigest != registration.ImageDigest ||
		!validHealthOutcome(runtimeResult.HealthOutcome) {
		return terminal(base, executor.clock.Now(), Denied, "runtime_contract_violation", boundedRuntimeEvidence(runtimeResult, limits.OutputBytes))
	}
	if runErr != nil {
		mapped := mapBoundaryError(runErr, "runtime_unavailable")
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), runtimeResult)
	}
	if runtimeResult.ResolvedImageDigest != registration.ImageDigest || runtimeResult.HealthOutcome != "healthy" {
		return terminal(base, executor.clock.Now(), Denied, "runtime_contract_violation", boundedRuntimeEvidence(runtimeResult, limits.OutputBytes))
	}
	if runtimeResult.ExitCode != 0 {
		return terminal(base, executor.clock.Now(), Failed, "container_exit", runtimeResult)
	}
	result, _ := terminal(base, executor.clock.Now(), "", "", runtimeResult)
	return result, nil
}

func (executor *Executor) reserve(ctx context.Context, id, fingerprint string) (*attempt, bool, error) {
	if err := contextError(ctx); err != nil {
		return nil, false, err
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if existing, found := executor.attempts[id]; found {
		if existing.fingerprint != fingerprint {
			return nil, false, NewError(Conflict, "attempt_identity_collision")
		}
		return existing, false, nil
	}
	created := &attempt{fingerprint: fingerprint, done: make(chan struct{})}
	executor.attempts[id] = created
	return created, true, nil
}

func (executor *Executor) finish(value *attempt, result Result, err error) {
	executor.mu.Lock()
	value.result, value.err = cloneResult(result), err
	close(value.done)
	executor.mu.Unlock()
}

func replayAttempt(ctx context.Context, value *attempt) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, contextError(ctx)
	case <-value.done:
		result := cloneResult(value.result)
		result.Provenance.Replayed = true
		return result, value.err
	}
}

func terminal(base Provenance, finished time.Time, code ErrorCode, reason string, runtime RuntimeResult) (Result, error) {
	base.FinishedAt = formatTime(finished.UTC())
	base.ExitCode = runtime.ExitCode
	base.TerminationSignal = runtime.TerminationSignal
	base.StandardOutput = streamEvidence(runtime.StandardOutput, runtime.OutputTruncated)
	base.StandardError = streamEvidence(runtime.StandardError, runtime.OutputTruncated)
	base.ResolvedImageDigest = runtime.ResolvedImageDigest
	base.ContainerSpecDigest = runtime.ContainerSpecDigest
	base.HealthCommandDigest = runtime.HealthCommandDigest
	base.HealthOutcome = runtime.HealthOutcome
	base.RuntimeDigest = runtime.RuntimeDigest
	if code == "" {
		base.Outcome, base.Reason = "succeeded", "execution_succeeded"
		return Result{StandardOutput: slices.Clone(runtime.StandardOutput), StandardError: slices.Clone(runtime.StandardError), Provenance: base}, nil
	}
	base.Outcome, base.Reason = outcome(code), reason
	return Result{StandardOutput: slices.Clone(runtime.StandardOutput), StandardError: slices.Clone(runtime.StandardError), Provenance: base}, NewError(code, reason)
}

func requestFingerprint(value Request) (string, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaximumInputBytes*2 {
		return "", NewError(InvalidInput, "execution_request")
	}
	return digestBytes(data), nil
}

func registrationKey(tool toolregistry.ToolReference, operation string) string {
	return tool.Name + "@" + tool.Version + "#" + tool.ArtifactDigest + "/" + operation
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func streamEvidence(data []byte, truncated bool) StreamEvidence {
	return StreamEvidence{Digest: digestBytes(data), Length: uint64(len(data)), Truncated: truncated}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func cloneRegistration(value Registration) Registration {
	value.FixedArguments = slices.Clone(value.FixedArguments)
	value.HealthArguments = slices.Clone(value.HealthArguments)
	value.FixedEnvironment = slices.Clone(value.FixedEnvironment)
	value.WritableMounts = slices.Clone(value.WritableMounts)
	return value
}

func cloneResult(value Result) Result {
	value.StandardOutput = slices.Clone(value.StandardOutput)
	value.StandardError = slices.Clone(value.StandardError)
	return value
}

func clonePublisherAuthority(value toolregistry.PublisherAuthority) toolregistry.PublisherAuthority {
	value.PublicKey = slices.Clone(value.PublicKey)
	return value
}

func cloneNetworkPolicy(value toolregistry.NetworkPolicy) toolregistry.NetworkPolicy {
	value.Protocols = slices.Clone(value.Protocols)
	return value
}

func cloneNetworkRequest(value NetworkRequest) NetworkRequest {
	value.Policy = cloneNetworkPolicy(value.Policy)
	return value
}

func boundedRuntimeEvidence(value RuntimeResult, limit uint64) RuntimeResult {
	if uint64(len(value.StandardOutput))+uint64(len(value.StandardError)) <= limit {
		return value
	}
	stdoutBytes := minUint64(uint64(len(value.StandardOutput)), limit)
	value.StandardOutput = slices.Clone(value.StandardOutput[:stdoutBytes])
	remaining := limit - stdoutBytes
	stderrBytes := minUint64(uint64(len(value.StandardError)), remaining)
	value.StandardError = slices.Clone(value.StandardError[:stderrBytes])
	value.OutputTruncated = true
	return value
}

func outcome(code ErrorCode) string {
	switch code {
	case InvalidInput:
		return "invalid"
	case Denied, Conflict:
		return "denied"
	case Canceled:
		return "canceled"
	case Timeout:
		return "timeout"
	case Failed:
		return "failed"
	default:
		return "unavailable"
	}
}

func containerName(attemptID, suffix string) string {
	return fmt.Sprintf("coh-%s-%s", attemptID, suffix)
}
