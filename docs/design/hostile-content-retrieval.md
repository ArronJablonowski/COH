# Hostile-content retrieval defense

| Item | Contract |
| --- | --- |
| Issue | CYB-75 / COH-E09-04 |
| Requirements | FR-044, SEC-001, SEC-016, EVAL-022 |
| Go boundary | `internal/workflow/retrievalguard` |
| Public schema | `contracts/workflow/v1/retrieval-inspection.schema.json` |
| Model-facing adapters | `internal/workflow/agentloop/skill_discovery.go`, `internal/workflow/agentloop/memory_lookup.go` |

## Purpose and invariant

Logs, documents, feeds, query and tool output, tool errors, memory, reports,
and attachments are hostile data even when they came from a previously
authorized system. Their text can describe evidence, but it cannot grant an
identity, change organization/tenant/case/task scope, authorize an action,
select a tool, provide a credential, or override policy.

Every source is an immutable artifact reference marked
`untrusted_content`. The retrieval guard releases only a separately written,
verified `application/json` artifact whose envelope contains the same trust
label and a `data` field. Source bytes and raw artifact handles are not exposed
by the model-facing skill-resource or memory activity result.

## Closed contract

The strict v1 contract freezes four records:

- a request binding request/idempotency identity, actor and revision, exact
  organization/tenant/case/task, source artifact and provenance, inspection
  profile, current policy, and deadline;
- a decision binding that request to a current policy and revocation snapshot;
- a completed inspection binding its sanitized artifact, sorted findings,
  redaction count, inspector identity, source digest, and provenance; and
- a durable record binding authorization, audit proof, idempotency, and chained
  provenance.

All objects are closed. The nine source kinds and nine finding codes are closed
enums. The strict profile requires active-format denial, secret redaction, and
directive neutralization. It also binds a byte limit and sorted media-type
allowlist. A malformed, unsupported, oversized, empty, partial, non-UTF-8,
digest-mismatched, non-canonical, or writer-mismatched result is never released.

## Authority separation and inspection

`Authority` receives the scoped authorization request and returns a canonical
allow or deny decision. The controller recomputes its digest and compares every
identity, policy, revision, time, and scope field. The decision must already be
issued, remain current, and expire no later than the operation deadline.

`Inspector` receives only `InspectionRequest`: an immutable source, strict
profile, intent digest, and deadline. It receives no actor, approval, policy
source, credential, connector, executor, tool, callback, or model authority.
The deterministic implementation resolves bytes through a narrow reader,
detects instruction, scope, authorization, credential, tool, exfiltration,
active-content, encoded-payload, and secret patterns, redacts secret values,
neutralizes active markup characters, and writes canonical JSON through a
narrow sanitized-artifact writer.

The detector is evidence and routing metadata, not an authorization engine.
Even ordinary content remains `untrusted_content`; absence of a finding never
makes text trusted instructions.

## Audit, replay, and recovery

An allow result is committed before release and its exact historical allow
event must append successfully. Audit failure therefore leaves a durable
record but returns no content reference. A retry reloads that record, rechecks
current authorization and revocation, re-verifies the sanitized artifact,
repairs the idempotent historical audit event, and appends a distinct event for
the fresh replay authorization before release.

Policy denial, changed replay, incomplete inspection, unavailable sanitized
artifact, and invalid audit proof append denial evidence. Reusing an
idempotency identity with changed request intent is denied. The record chains
the source provenance digest, so sanitized output cannot be detached from its
origin. SQLite close/reopen coverage proves recovery after commit plus lost
audit response without reading the hostile source a second time.

## Model-facing integration

Progressive skill search and detail remain metadata-only. Resource fetch now
resolves the signed immutable source and immediately invokes the retrieval
guard as `document`; its result exposes the sanitized inspection artifact plus
source and audit digests, never the raw `Artifact` field.

Memory lookup still resolves through the class-bound CYB-72 controller and its
current access/review/retention checks. The adapter immediately invokes the
retrieval guard as `memory`; its result exposes no raw memory `Record`. Both
adapters bind the same case, task, actor, policy, and deadline and require an
explicit actor revision, strict inspection profile, and inspection
idempotency key.

Other ingestion adapters must use the same controller with the corresponding
closed source kind before adding a reference to model context. Implementing a
new raw-content activity is not an extension point.

## Deployment and rollback

The generic metadata store adds the case-scoped `retrieval` kind; existing SQL
tables require no physical migration. Deploy readers and the retrieval guard
before enabling guarded model-facing adapters. Existing `skill` and `memory`
records remain readable as sources, but their artifacts are not eligible for
model context until a successful inspection record and audit proof exist.

Rollback first disables model-facing retrieval. A prior binary rejects the
unknown `retrieval` metadata kind and therefore fails closed. Durable records
and sanitized artifacts remain for forward recovery and audit; they are not
rewritten as trusted prompts or instructions.

## Verification

`scripts/verify_hostile_content_retrieval.sh` checks schema closure, boundary
shape, all source kinds, adversarial sanitization, policy/revocation denial,
audit failure and replay, agent-loop integration, SQLite restart recovery,
repeated execution, race detection, vet, architecture, static analysis, file
sizes, Markdown links, and clean diffs. The complete CI baseline supplies the
final repository-wide gate.
