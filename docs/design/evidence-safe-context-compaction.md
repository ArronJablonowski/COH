# Evidence-safe context compaction

| Field | Value |
|---|---|
| Issue | COH-E08-05 / CYB-66 |
| Requirements | FR-027, SEC-016 |
| Contract | `coh.context-compaction/v1` / `1.0.0` |
| Boundary | `internal/workflow/contextcompact` |

## Decision

Compaction replaces large workflow context with a reference to a separate
immutable JSON summary artifact. It never replaces or rewrites the evidence
manifest. The durable compaction state retains the exact ordered source list
and its canonical manifest digest, plus only the summary artifact's digest,
media type, classification, and length.

Every source descriptor contains a resolvable UUIDv7 evidence ID and SHA-256
digest, original source time, normalized UTC nanosecond time, original
timezone, source precision, clock uncertainty, sequence, ordering confidence,
result state, completeness, and uncertainty. Negative results, telemetry gaps,
conflicts, truncation, unavailable sources, overlapping clocks, and unknowns
therefore remain explicit after the source content leaves the active context.

## Untrusted-data boundary

Every source and the derived summary reference have the fixed
`untrusted_evidence` trust label. Public requests, durable state, and writer
inputs contain references and typed metadata only;
they have no prompt, raw content, instruction, policy authority, approval,
credential, tool, connector, executor, callback, or generic function field.

The narrow `SummaryWriter` receives a case/run/task operation identity, ordered
source descriptors, and a deadline. An adapter may resolve those references
inside its own evidence-reading boundary, but it receives no capability that
can evaluate policy, approve work, or invoke a tool. Embedded evidence text is
data to that adapter and has no path to broker authority.

Before first persistence, the narrow `EvidenceResolver` proves that every
evidence ID exists in the bound case and resolves to the exact immutable
digest. It returns no content. An unresolvable, cross-case, or digest-mismatched
source prevents both durable intent creation and summary generation.

Only an `application/json` immutable artifact reference is accepted. A missing,
empty, oversized, malformed, or otherwise invalid reference never becomes a
completed compaction.

The workflow result carries the same canonical source-manifest digest. Before
returning a replacement reference, `ReplacementReferences` recomputes it from
the full returned manifest and denies any substitution, reordering, or metadata
change, even when every individual source descriptor remains well formed.

## Durable sequence

One compaction follows this order:

1. Strictly validate scope, times, the ordered source manifest, and the
   idempotency key.
2. Canonically digest the complete intent and idempotency identity.
3. Load and fully validate any existing state; return only an exact completed
   replay or deny changed bytes.
4. For a new intent, resolve each evidence ID in the exact case and verify its
   immutable digest without loading content into the controller.
5. Atomically persist `writing` with the full source manifest and chained
   provenance before calling the writer.
6. Ask the narrow writer to create a separate immutable summary artifact.
7. Validate the artifact reference, then compare-and-save `completed` with the
   reference and a new provenance revision.

The returned workflow-facing result contains the summary reference plus a copy
of the complete source manifest. A caller can replace context content with the
summary only through `ReplacementReferences`, which admits completed,
explicitly untrusted results with a valid manifest. The caller retains that
manifest for citation, ordering, and completeness decisions.

## Replay and recovery

Scope, run, task, compaction ID, policy digest, provider route, source order and
metadata, creation/deadline times, and idempotency identity are immutable. Any
change on replay is denied. A completed replay returns the exact stored summary
and provenance without calling the writer.

An exact concurrent replay of `writing` returns retryable `in_progress` and
does not disturb the active writer. If a process restarts and the durable
deadline elapses while state remains `writing`, COH cannot prove whether an
external artifact write happened. It compare-and-saves `uncertain` and does not
call the writer again. A lost response after the completed save is safe:
restart loads and returns the completed record without another write.
Cancellation, timeout, dependency failure, and invalid writer output after
`writing` is durable also produce a fail-closed uncertain state with a fixed
reason code; raw errors are not retained.

Every load recomputes the intent and provenance digests. The provenance chain
covers source metadata, summary reference, status, reason, prior digest,
timestamps, and revision. Scope drift, reordered or altered sources, changed
negative/completeness/uncertainty state, and store tamper are denied.

## Contract and migration

`contracts/workflow/v1/context-compaction.schema.json` freezes strict intent
and state records. Runtime decoding recursively rejects duplicate, missing,
unknown, malformed, trailing, oversized, unsupported, and noncanonical input.
Published fixtures are exact canonical bytes.

This adds a new side record and does not mutate existing agent-loop run/task
records, so the generic SQLite/PostgreSQL metadata layout needs no DDL change.
Deployments must supply a durable begin/compare-and-save store. A later change
to source semantics, summary media type, recovery, or digest identity requires
a new contract version and replay/migration evidence.

Existing agent-loop histories remain on their pinned workflow definition and
are not retroactively compacted. A workflow that adopts compaction must publish
a new definition/version, invoke the compactor before scheduling with the
replacement digest, and retain the side-record provenance. This is the
workflow-version migration boundary; old histories replay unchanged.

## Enforcement

- Reflection tests freeze the data-only public surface and narrow interfaces.
- The resolver verifies case-scoped evidence existence and digest equality
  without returning raw content.
- Source validation requires contiguous order, unique evidence IDs, fixed trust
  labels, explicit semantic enums, and bounded canonical identities.
- Runtime tests cover preservation, exact replay, changed-input denial,
  ambiguous begin/completion, malformed summary references, dependency errors,
  cancellation, scope/state tamper, and strict decoding.
- `scripts/verify_context_compaction.sh` runs schema/fixture and forbidden-field
  checks plus focused, repeated, race, vet, static, architecture, file-size,
  link, and diff gates.
