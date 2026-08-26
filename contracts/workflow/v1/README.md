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
