package nativeexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	artifacts     ArtifactPreparer
	sandbox       Sandbox
	clock         Clock
	registrations map[string]Registration
	mu            sync.Mutex
	attempts      map[string]*attempt
}

func New(resolver Resolver, authorizer Authorizer, artifacts ArtifactPreparer, sandbox Sandbox, clock Clock,
	registrations []Registration) (*Executor, error) {
	if resolver == nil || authorizer == nil || artifacts == nil || sandbox == nil || clock == nil ||
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
	return &Executor{resolver: resolver, authorizer: authorizer, artifacts: artifacts, sandbox: sandbox, clock: clock,
		registrations: values, attempts: make(map[string]*attempt)}, nil
}

func (executor *Executor) Execute(ctx context.Context, request Request) (Result, error) {
	if executor == nil || executor.resolver == nil || executor.authorizer == nil || executor.artifacts == nil ||
		executor.sandbox == nil || executor.clock == nil {
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
	started := executor.clock.Now().UTC()
	base := Provenance{AttemptID: request.AttemptID, OrganizationID: request.OrganizationID, TenantID: request.TenantID,
		CaseID: request.CaseID, ActorID: request.ActorID, Tool: request.Tool, Operation: request.Operation,
		RequiredTier: request.RequiredTier, ArtifactDigest: request.Tool.ArtifactDigest,
		StartedAt: formatTime(started), Outcome: "denied"}
	if started.IsZero() {
		return terminal(base, executor.clock.Now(), Unavailable, "clock_unavailable", SandboxResult{})
	}
	registration, found := executor.registrations[registrationKey(request.Tool, request.Operation)]
	if !found {
		return terminal(base, executor.clock.Now(), Denied, "binary_not_registered", SandboxResult{})
	}
	rawInputDigest, err := inputRequestDigest(request.Inputs)
	if err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), SandboxResult{})
	}
	authorizationRequest := AuthorizationRequest{AttemptID: request.AttemptID, OrganizationID: request.OrganizationID,
		TenantID: request.TenantID, CaseID: request.CaseID, ActorID: request.ActorID, Tool: request.Tool,
		Operation: request.Operation, RequiredTier: request.RequiredTier, InputDigest: rawInputDigest}
	authority, err := executor.authorizer.Authorize(ctx, authorizationRequest)
	if err != nil {
		mapped := mapAuthorizationError(err)
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), SandboxResult{})
	}
	if err := validateDispatchAuthority(authority, authorizationRequest, executor.clock.Now().UTC()); err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), SandboxResult{})
	}
	base.AuthorizationID, base.PolicyDecisionDigest = authority.AuthorizationID, authority.DecisionDigest
	capability, err := executor.resolver.ResolveOperation(ctx, request.Tool, request.Operation,
		request.RequiredTier, authority.RuntimeCeiling, request.Publisher)
	if err != nil {
		mapped := mapRegistryError(err)
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), SandboxResult{})
	}
	if err := validateCapability(request, authority.RuntimeCeiling, capability); err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), SandboxResult{})
	}
	base.ManifestDigest, base.ManifestID = capability.ManifestDigest, capability.ManifestID
	base.EffectiveCeiling = capability.EffectiveCeiling
	input, err := encodeInputs(capability.Operation.InputFields, request.Inputs)
	if err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), SandboxResult{})
	}
	environment := cleanEnvironment(registration.FixedEnvironment)
	base.ArgumentDigest = digestBytes(canonicalStrings(registration.FixedArguments))
	base.EnvironmentDigest = digestBytes(canonicalStrings(environment))
	base.InputDigest = digestBytes(input)
	prepared, err := executor.artifacts.Prepare(ctx, registration.ExecutablePath,
		request.Tool.ArtifactDigest, capability.Operation.ResourceLimits.EphemeralStorageBytes)
	if err != nil {
		return terminal(base, executor.clock.Now(), Code(err), Reason(err), SandboxResult{})
	}
	if prepared.Cleanup == nil || prepared.Path == "" || prepared.Digest != request.Tool.ArtifactDigest {
		if prepared.Cleanup != nil {
			_ = prepared.Cleanup()
		}
		return terminal(base, executor.clock.Now(), Denied, "prepared_artifact_binding", SandboxResult{})
	}
	limits := capability.Operation.ResourceLimits
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(limits.WallTimeMilliseconds)*time.Millisecond)
	defer cancel()
	plan := Plan{ExecutablePath: prepared.Path, ArtifactDigest: prepared.Digest, Arguments: slices.Clone(registration.FixedArguments),
		Environment: environment, Input: input, Limits: limits, Network: capability.Operation.NetworkPolicy}
	sandboxResult, runErr := executor.sandbox.Execute(runCtx, plan)
	cleanupErr := prepared.Cleanup()
	if cleanupErr != nil {
		return terminal(base, executor.clock.Now(), Unavailable, "artifact_cleanup_failed", sandboxResult)
	}
	if uint64(len(sandboxResult.StandardOutput))+uint64(len(sandboxResult.StandardError)) > limits.OutputBytes ||
		sandboxResult.ExitCode < -1 {
		return terminal(base, executor.clock.Now(), Denied, "sandbox_contract_violation", SandboxResult{})
	}
	if runErr != nil {
		mapped := mapExecutionError(runCtx, runErr)
		return terminal(base, executor.clock.Now(), Code(mapped), Reason(mapped), sandboxResult)
	}
	if sandboxResult.ExitCode != 0 {
		return terminal(base, executor.clock.Now(), Failed, "process_exit", sandboxResult)
	}
	result, _ := terminal(base, executor.clock.Now(), "", "", sandboxResult)
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

func terminal(base Provenance, finished time.Time, code ErrorCode, reason string,
	sandbox SandboxResult) (Result, error) {
	base.FinishedAt = formatTime(finished.UTC())
	base.ExitCode = sandbox.ExitCode
	base.TerminationSignal = sandbox.TerminationSignal
	base.StandardOutput = streamEvidence(sandbox.StandardOutput, sandbox.OutputTruncated)
	base.StandardError = streamEvidence(sandbox.StandardError, sandbox.OutputTruncated)
	if code == "" {
		base.Outcome, base.Reason = "succeeded", "execution_succeeded"
		return Result{StandardOutput: slices.Clone(sandbox.StandardOutput), StandardError: slices.Clone(sandbox.StandardError), Provenance: base}, nil
	}
	base.Outcome, base.Reason = outcome(code), reason
	return Result{StandardOutput: slices.Clone(sandbox.StandardOutput), StandardError: slices.Clone(sandbox.StandardError), Provenance: base}, NewError(code, reason)
}

func mapExecutionError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if code := Code(err); code != Unavailable || Reason(err) != "native_executor_unavailable" {
		return err
	}
	return NewError(Unavailable, "sandbox_unavailable")
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

func validateRequest(ctx context.Context, value Request) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !uuidPattern.MatchString(value.AttemptID) || !tokenPattern.MatchString(value.Tool.Name) ||
		!uuidPattern.MatchString(value.OrganizationID) || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.CaseID) || !uuidPattern.MatchString(value.ActorID) ||
		!versionPattern.MatchString(value.Tool.Version) || !digestPattern.MatchString(value.Tool.ArtifactDigest) ||
		!tokenPattern.MatchString(value.Operation) || !lowRiskTier(value.RequiredTier) ||
		len(value.Inputs) > 128 {
		return NewError(InvalidInput, "execution_request")
	}
	return nil
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

func lowRiskTier(value string) bool { return value == "T0" || value == "T1" }

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
	value.FixedEnvironment = slices.Clone(value.FixedEnvironment)
	return value
}

func cloneResult(value Result) Result {
	value.StandardOutput = slices.Clone(value.StandardOutput)
	value.StandardError = slices.Clone(value.StandardError)
	return value
}
