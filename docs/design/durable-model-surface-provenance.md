# Durable model-surface provenance

| Field | Decision |
|---|---|
| Stable key | COH-E25-04 / CYB-186 |
| Contract | `contracts/model-surface/v1` |
| Requirements | FR-014, FR-027, FR-038, FR-044, SEC-011, SEC-015, SEC-016, SEC-020 |
| Status | v1 contract frozen; implementation proceeds through short tasks in Linear |

## Decision

COH constructs provider-visible context as a deterministic projection of
durable typed records and immutable artifacts. The projector is a mandatory
guard between workflow/context assembly and every provider adapter. Provider
adapters receive an already-validated inference request plus a digest-bound
surface binding; they cannot admit unbound messages or tools.

This makes the answer to “what exactly did the model see?” a durable,
replayable record rather than a reconstruction from application logs. It also
prevents retrieved content, model output, or an extension from silently
converting itself into an instruction or authority surface.

## Authority and data flow

```text
durable records / immutable artifacts
                |
                v
scope + vocabulary + trust verification
                |
                v
deterministic ordered projector
                |
                +--> durable projection + surface digest
                |
                v
authorization/audit-bound inference binding
                |
                v
model-surface admission boundary
                |
                v
qualified provider adapter
                |
                v
lineage-bound stream + explicit terminal outcome
```

The source resolver and artifact reader are narrow, read-only ports. They expose
no repository mutation, connector, credential, policy, approval, audit, broker,
runner, E-stop, or generic callback. The projector can render data; it cannot
authorize a tool action.

Provider-request admission accepts dispatch controls but rejects caller-supplied
messages, tools, or model-surface metadata. It revalidates the sealed projection
and every rendered item, derives the provider identifier, constructs the exact
typed provider messages and sorted tool definitions, seals the inference
binding, and then runs the provider contract decoder. Production dispatch uses
`provider.SurfaceGateway`, whose input type is the opaque admitted inference;
vendor adapters remain low-level translation boundaries.

Each provider attempt owns a serialized stream session. The session starts with
the complete input source set; every chunk or typed item carries a nonempty
subset, a domain-separated content digest, and a contiguous sequence. A
terminal record always names an explicit outcome and seals the exact assembled
bytes—including the empty byte sequence or partial bytes from an interrupted
attempt. State advances only after the durable event writer succeeds.

Fallback is a new attempt and a new provider binding. It is permitted only from
an explicitly failed primary terminal record, with the same request, scope,
run, actor, projection, ordered sources, artifact set, composition, vocabulary,
and input-surface digest. Cancellation, timeout, interruption, uncertainty, and
denial therefore cannot silently become fallback.

Compaction selects an exact contiguous range from a sealed projection and
resolves coverage metadata through a read-only authoritative port. Prior
replacements expand to their original leaf sources; duplicate, missing,
cross-scope, reordered, or overlapping coverage denies closed. Leaf records
retain evidence identifiers, normalized and original time semantics, result
state (including negative and gap), completeness, and uncertainty. The summary
artifact must be immutable and decode as a data-role
`compaction_replacement` surface payload before the coverage and replacement
digests are sealed.

Recovery is an append-only, digest-linked transition chain updated with atomic
compare-and-swap. Exact prepare replay is idempotent; changed replay and stale
writers are denied. Before any transition is persisted or resumed, COH reloads
the sealed projection, binding, and stream cursor and reprojects every source
and artifact through the normal resolver. A crash in `prepared` resumes
verification, `verified` may dispatch, `dispatched` becomes uncertain rather
than being invoked twice, `streaming` resumes from the durable cursor, and a
terminal state is complete. Forks require a distinct request and attempt with
an explicit terminal parent. Provider fallback requires a failed terminal
parent, a distinct provider/attempt, and identical input lineage.

## Invariants

1. Every visible item has exactly one durable source record and immutable
   content digest.
2. Only registered `model_surface` event types have projection rules. Log-only
   and live coordination events can never enter model context.
3. Scope is exact across organization, tenant, case, task, and run.
4. Projected ordinals are consecutive and deterministic. Aggregated source IDs
   and artifact digests must be exact derivations of ordered items.
5. Untrusted external, retrieved, and model-originated content is always data,
   never an instruction, tool schema, policy, or approval.
6. Dispatch binds the projection and surface to current provider,
   authorization, policy, approval, audit, profile composition, and deadline.
7. Streaming never loses request, attempt, projection, binding, or source
   lineage. Silence and interruption are explicit outcomes.
8. Compaction replaces an exact source set and retains complete leaf coverage
   and evidentiary metadata.
9. Restart and replay re-resolve immutable inputs and reproduce the same surface
   digest before proceeding.

## Failure posture

Missing or mutable content, unknown versions, cross-scope references,
noncanonical ordering, stale revisions, duplicate records, digest mismatch,
hostile instructions, provider lineage drift, ambiguous streaming, and coverage
loss deny closed. Failures are durable typed outcomes; they do not fall back to
unbound raw prompt construction.

## Delivery sequence

The contract freeze is followed by strict Go records/decoders, source
resolution, deterministic projection, provider-request admission, stream
lineage, compaction coverage, recovery/adversarial behavior, and checksummed
release evidence. Generated architecture catalogs in CYB-185 consume this
vocabulary only after the runtime implementation is complete.
