# Durable agent loop contract v1

`agent-loop.schema.json` freezes the persisted COH-E08-01 run and current-step
records as strict `coh.domain/v1` common envelopes. Their `data` payloads carry
actor, workflow, policy,
provider-route, state, revision, transition sequence, deadlines, immutable
artifact references, intent/receipt digests, timestamps, and chained
provenance. They never contain prompts, evidence bytes, credentials, connector
responses, or executable callbacks.

Every transition is committed atomically with a durable outbox event through
the guarded workflow repository. Planning calls only the bounded
`ModelProvider` port through `coh.agent-loop.plan.v1`. Consequential work calls
only `ActionAuthority` through `coh.agent-loop.authorized-action.v1`; a crash
after dispatch but before receipt persistence becomes `uncertain` and is not
automatically submitted again.

The versioned `coh.agent-loop.v1` definition remains behind `WorkflowEngine`
and has a retained Temporal replay fixture. Incompatible logic requires a new
workflow definition and migration/replay evidence.

This contract implements CYB-60 / COH-E08-01 for FR-011, FR-012, and FR-014.

## Typed agent phases

`agent-phase.schema.json` freezes the CYB-68 / COH-E08-02 input and output
records for `plan → act → observe → review`. Every record binds the trace,
cycle, exact input set, immutable output artifact, and bounded retry policy.
Plan output binds one action intent. Act output binds the broker receipt and
evidence. Observe records completeness and negative-result state. Review
returns typed claims/findings with evidence, counterevidence, confidence,
unknowns, recommended next steps, and an accepted/revise disposition.

The coordinator stores only these identities and references through the
durable agent loop. Raw prompts, claim text, findings, evidence bytes, and
provider/tool payloads remain behind immutable artifact references.

## Run and task budgets

`run-budget.schema.json` freezes `coh.run-budget/v1` plans and durable ledgers
for run/task limits, atomic worst-case reservations, derived delegation
hierarchy, exact settlement, and crash-safe replay. See
`../../../docs/design/run-task-budget-enforcement.md` for the enforcement and
recovery model. This implements CYB-65 / COH-E08-04 and FR-017. Every plan
binds one tenant/case run to the exact policy and provider route. Integer-only
limits cover tokens, cost micros, elapsed nanoseconds, tool calls, query rows,
evidence bytes, delegation depth, fanout, and concurrency.

Each task supplies a trusted worst-case claim. The budget authority atomically
charges cumulative dimensions and reserves concurrency before the agent loop
can persist the scheduled task. Claims, reservations, settlements,
idempotency identities, and prior state are digest-bound into the ledger's
provenance. Actual usage may be recorded only within the reservation; unused
cumulative capacity is not refunded, while terminal settlement releases the
renewable concurrency slot.

The decoder rejects duplicate, unknown, missing, nested-missing, trailing,
malformed, oversized, or unsupported records. The contract contains no prompt,
price text, evidence content, credential, connector, policy callback, or model
authority field.

## Evidence-safe context compaction

`context-compaction.schema.json` freezes `coh.context-compaction/v1` intent and
durable state records for CYB-66 / COH-E08-05, FR-027, and SEC-016. Every
ordered source retains a resolvable evidence ID and digest, source and
normalized time, original timezone, precision, clock uncertainty, order
confidence, negative/gap/conflict state, completeness, uncertainty, and a
fixed untrusted-data label.

A data-only resolver verifies every evidence ID in the bound case against its
exact immutable digest before a new compaction is persisted or summarized.

Summary content is written as a separate immutable JSON artifact. Durable
compaction state keeps only its bounded artifact reference, the complete
ordered source manifest, and a canonical digest that prevents manifest
substitution in the workflow result. Both source and summary references remain
explicitly `untrusted_evidence`. The record has no prompt, raw evidence, instruction,
tool, policy authority, approval, credential, connector, callback, or executor
field.
