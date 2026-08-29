# Typed agent phases

This package implements the versioned plan, act, observe, and review protocol
over the durable agent loop. A trace and bounded retry policy are bound into
the run's immutable input references. Each phase step receives a deterministic
UUIDv7 identity derived from the run, trace, cycle, and phase; the phase code
is recoverable from the step identity while the complete identity remains
bound to the supplied trace and cycle.

The legal graph is:

`plan → act → observe → review → accepted`

A review may instead request a new plan cycle, up to the externally enforced
review-cycle ceiling. Safe planning/observation/review retries use the durable
step attempt count. Exhaustion becomes a durable failure. An action that has
reached `dispatching` is never retried; a missing receipt becomes uncertain.

Model phases go through a wrapper that gives the provider only a typed phase
operation. It resolves and validates the structured result by immutable
artifact digest before the durable activity succeeds. The coordinator resolves
the same immutable result again and verifies phase, trace, cycle, exact input
set, and artifact binding before allowing a transition.

Plan output binds one exact tool-intent digest. Act accepts only the
`ActionAuthority` path and returns the broker receipt/evidence reference.
Observe records completeness and negative-result state. Review returns typed
claims and findings with statement/summary digests, evidence, counterevidence,
confidence basis points, unknowns, recommended next steps, and a bounded
accepted/revise disposition.

Only identifiers, digests, bounds, statuses, timestamps, and immutable
references enter durable state. There is no connector, executor, credential,
runner, shell, HTTP, policy-engine, or generic callback dependency.

## Accuracy contract and bounded repair

`TaskContract` adds a versioned production contract for the objective, output
shape, capability requirements, workspace, tool allowlist, safety boundary,
validator profile, and repair policy. `ModelExecutionProfile` is qualified from
the exact provider/model digest and advertised capabilities; it selects stable
prompt fragments, roles, reasoning controls, context/output limits, structured
output, and tool conventions without benchmark-specific model-name branches.

The compiler turns those records into a concise prompt with explicit completion
criteria and untrusted-content boundaries. The repair controller then generates
an artifact, validates it outside the model, accepts it when mandatory checks
pass, or supplies only stable actionable diagnostics for at most two repairs.
Every attempt binds the contract, model profile, artifact, budget settlement,
validator, diagnostics, prior validation, and final provenance digest. A
confirmed or uncertain external side effect is never repeated. Security-sensitive
work fails closed after exhaustion; advisory work may be returned only as
explicitly incomplete.

`ValidationRecordV2` is backward-compatible with existing phase traces because
it is an additive result record rather than a mutation of the v1 durable phase
schema. The validator registry is deterministic, allowlisted, workspace-bound,
and side-effect-free. It currently supplies production gates for workspace,
JSON, Python, Sigma, SPL, KQL, ES|QL, YARA-L, AppSec, exploit-analysis, and
prompt-injection artifacts.

The supported `coh-agent` entrypoint runs the same compiler, Ollama provider
route, validator registry, and bounded repair controller. It requires an exact
model digest, an absolute workspace, a versioned task-contract file, and a
deadline, and emits a versioned JSON result envelope. Model output is applied as
a native JSON-Schema-constrained change set; COH never strips fences or rewrites
an answer into a passing artifact.
