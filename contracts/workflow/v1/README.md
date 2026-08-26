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
