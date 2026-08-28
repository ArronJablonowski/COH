# Durable model-surface provenance v1

| Field | Value |
|---|---|
| Stable key | COH-E25-04 / CYB-186 |
| Contract version | `1.0.0` |
| Projection version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Requirements | FR-014, FR-027, FR-038, FR-044, SEC-011, SEC-015, SEC-016, SEC-020 |

This contract makes the exact surface sent to a model reproducible and
auditable. Every visible message, prompt section, tool schema, retrieved context
item, compaction replacement, and policy notice is projected from one durable
typed record whose bytes are immutable or from one immutable digest-bound
artifact. A provider request cannot be admitted from caller-supplied visible
bytes alone.

The contract introduces no model-controlled installation, generic shell, HTTP,
filesystem, credential, connector, runner, policy, approval, audit, evidence,
E-stop, or validator authority. Model-surface provenance describes input; it
does not authorize an action.

## Records

| Schema | Purpose |
|---|---|
| `event-vocabulary.schema.json` | Versioned definitions that classify events as durable model-surface, durable log-only, or ephemeral live coordination |
| `model-surface-source.schema.json` | Scope-exact durable source descriptor with immutable content binding and instruction disposition |
| `model-surface-projection.schema.json` | Exact ordered projected items, source IDs, artifact digests, composition digest, and surface digest |
| `inference-surface-binding.schema.json` | Provider attempt binding to the verified projection and current authorization/audit decisions |
| `model-surface-stream.schema.json` | Ordered chunk/item/terminal lineage with explicit empty, interrupted, canceled, timeout, failed, and uncertain outcomes |
| `compaction-replacement.schema.json` | Source-covering summary replacement that preserves evidence, time, order, negative results, uncertainty, and completeness |
| `model-surface-transition.schema.json` | Durable phase, provider-attempt, stream-cursor, and terminal state used for exact restart recovery |

All records are schema-closed. Implementations must reject duplicate JSON names,
trailing values, invalid UTF-8, excessive size or depth, unsupported versions,
unknown fields, noncanonical timestamps, duplicate or nonconsecutive ordinals,
unsorted set-like arrays, cross-scope references, changed revisions, and digest
drift.

## Event vocabulary

Each event type has one version, class, persistence rule, producer, closed
consumer set, payload schema digest, and projection rule.

- `model_surface` events are durable and require exactly one of the six
  projection rules. Only these records can source model-visible items.
- `log_only` events are durable and have `projection_rule=none`. They may be
  audited or diagnosed but cannot appear in a model request.
- `live_coordination` signals are ephemeral and have `projection_rule=none`.
  They cannot be replayed as history or used as model context.

Unknown event types, version drift, an unregistered producer or consumer, and a
class/persistence/projection mismatch deny projection.

## Durable source and content binding

A source binds the exact organization, tenant, case, task, run, record revision,
event definition, occurrence time, sequence, record digest, and immutable
content digest. Content is either a validated durable-record projection or an
immutable artifact; the contract stores its ID, digest, media type, byte length,
classification, and `immutable=true`, not mutable provider-ready bytes.

Retrieved, external, and model-originated content is always
`untrusted_data_only`. It cannot become a system/developer instruction, tool
definition, policy, approval, or action intent merely because it appears in a
source record. Trusted control/system instruction dispositions require an
allowlisted event definition and fresh scope-exact authority outside the
serialized document.

The source digest is:

```text
sha256("COH-MODEL-SURFACE-SOURCE-V1\0" || COH-CJ-1(source_without_source_digest))
```

## Deterministic projection and inference admission

The projector resolves every source and content binding through narrow
read-only ports, verifies the current vocabulary, exact scope and immutable
digest, applies the registered projection rule, and emits consecutive ordinals.
The `ordered_source_record_ids` array must equal the item projection in order;
`artifact_digests` is the unique lexicographically sorted set of immutable
artifact digests referenced by those items.

The surface digest covers the exact provider-visible canonical item sequence:

```text
sha256("COH-MODEL-SURFACE-BYTES-V1\0" || COH-CJ-1(provider_visible_items))
```

The projection digest covers the projection record without
`projection_digest`. An inference binding then repeats the exact ordered source
IDs and artifact digests and binds projection/version, vocabulary, composition,
surface, actor, provider, authorization, policy, approval, audit reservation,
creation time, and deadline:

```text
sha256("COH-INFERENCE-SURFACE-BINDING-V1\0" || COH-CJ-1(binding_without_binding_digest))
```

Provider dispatch must carry and verify this binding. Missing sources, mutable
content, unsupported events, cross-scope data, noncanonical order, untrusted
instructions, changed replay, or any digest mismatch deny before network or
process invocation.

## Streaming and terminal outcomes

Every stream event binds the request, attempt, inference binding, projection,
input surface, monotonically increasing sequence, relevant source IDs, and
chunk/assembled digests. `started`, `chunk`, and `item` are pending. A terminal
record explicitly states `succeeded`, `empty`, `interrupted`, `canceled`,
`timeout`, `failed`, or `uncertain`; an empty result is not inferred from absent
events. Only a terminal record can complete an attempt.

Provider fallback creates a new attempt and binding while retaining the same
verified projection and surface digest. It never silently splices chunks from
different attempts. Ambiguous or interrupted output cannot be treated as a
successful assembled message.

## Source-covering compaction

A compaction replacement lists every covered source in original order and binds
its record/evidence IDs, digest, normalized time, original timezone, precision,
clock uncertainty, order confidence, result state, completeness, and
uncertainty. The separate summary artifact is immutable and untrusted data. A
replacement is admissible only when the covered set exactly equals the sources
it replaces and the coverage and replacement digests verify.

Compaction cannot erase negative results, gaps, ambiguous order, partial or
truncated completeness, or uncertainty. Nested replacements expand to their
original leaf coverage for fork, replay, and audit comparison.

## Recovery and compatibility

The durable transition advances through `prepared`, `verified`, `dispatched`,
`streaming`, and `terminal`. It records the exact projection/binding digests,
provider route and attempt, stream cursor, prior transition digest, and revision.
Restart re-resolves all sources and artifacts and verifies the same surface
digest before resuming. Process memory, provider state, or an earlier successful
verification is never sufficient authority.

See `compatibility-matrix.md` for replay, fork, fallback, compaction, and mixed
version behavior.

## Forbidden durable fields

These control records must never contain raw prompt/evidence content,
credentials or secret values, private paths, provider tokens, executable
payloads, callbacks, function pointers, mutable URLs, or authority objects.
Content remains in its owning immutable record/artifact store and is resolved
only at the guarded projection boundary.
