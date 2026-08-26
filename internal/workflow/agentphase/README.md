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
