# Session and case memory namespaces

| Item | Contract |
| --- | --- |
| Issue | CYB-72 / COH-E09-03 |
| Requirements | FR-026, SEC-015 |
| Go boundary | `internal/workflow/memorynamespace` |
| Public schema | `contracts/workflow/v1/memory-namespace.schema.json` |
| Orchestration adapter | `internal/workflow/agentloop/memory_lookup.go` |

## Purpose

COH memory is four data classes, not a shared semantic cache. The controller
keeps session working state, case knowledge, analyst preferences, and reviewed
organization knowledge in class-bound stores. A store constructed for one
namespace cannot load, recover, or commit another namespace.

Memory contains only an immutable `domain.ArtifactRef` plus bounded typed
metadata. Content stays in the artifact boundary. The contract has no field
for prompts, instructions, evidence bytes, query handles, credentials, paths,
URLs, callbacks, connectors, or executors.

Artifacts must be canonical JSON references. Each namespace accepts only its
matching value type: `session_state_reference`, `case_memory_reference`,
`analyst_preference_reference`, or `reviewed_organization_reference`.
Cross-class labels and generic prompt, query-handle, connector, or executor
labels are invalid input.

## Namespace identity and retention

| Namespace | Exact identity | Required owner/review | Retention class | Hard maximum |
| --- | --- | --- | --- | --- |
| `session` | organization + tenant + case + session + actor | requesting actor is the subject actor | `session_ephemeral` | 30 days |
| `case` | organization + tenant + case | current access decision | `case_record` | 10 years |
| `analyst_preference` | organization + tenant + subject actor; no case/session | requesting actor is the subject actor | `analyst_preference` | 2 years |
| `reviewed_organization` | organization + tenant; no case/session/subject | current independent review authority | `reviewed_organization` | 1 year |

The caller supplies an earlier expiry and a retention-policy digest. An expiry
outside the namespace bound is denied. Reads deny expired records before
returning the artifact reference. Storage identity includes every populated
scope field, the namespace, and the bounded key, so namespace and scope cannot
alias.

## Default-deny access

Every read and write asks `Authority` for a fresh decision. The controller
recomputes both sides of the decision binding. The access-request digest binds:

- request and actor IDs;
- read or write operation;
- namespace and exact scope;
- key and immutable value digest (covering artifact digest, media type,
  classification, length, and namespace-specific value type);
- retention-policy digest;
- current policy digest; and
- request deadline.

The returned decision must bind that exact request, be canonically digest
valid, already issued, currently unexpired, and no longer-lived than the
operation deadline. A false, malformed, stale, substituted, canceled, timed
out, or unavailable decision fails closed.

Reviewed organization memory has a second independent gate. Its review record
binds a reviewer different from the writer, a revision, authority digest,
review time, and validity end. `ReviewAuthority` is queried on both write and
read. Revocation or expiry therefore prevents future resolution even though
the immutable metadata remains durable.

## Writes, replay, and provenance

A write supplies an expected revision. Creation requires zero; replacement
requires the exact current revision. Each accepted replacement points to the
previous provenance digest. The new provenance digest covers the entire
canonical record, including namespace, scope, value, retention, review,
authorization decisions, times, and revision.

One storage transaction atomically commits:

1. the optimistic current record; and
2. an immutable idempotency receipt containing the exact committed record.

Exact replay recovers the receipt and rechecks current authorization before
returning an owned copy. Reusing the same idempotency identity with a changed
intent is denied. Receipts remain resolvable after later revisions, so a retry
cannot silently become the newest value. SQLite close/reopen coverage proves
current records and old receipts survive restart.

## Reads and orchestration

A read resolves only through the class-bound store selected by the request
namespace. The controller then rechecks record canonical invariants,
provenance, exact scope and key, retention, current access, and—where
applicable—current review authority.

The agent loop receives `BoundedMemoryLookup`, a one-method read-only port. It
cannot write memory or receive artifact bytes or execution authority. The
controller remains the security boundary; the orchestration adapter only maps
typed errors without weakening them.

## Storage migration and rollback

The generic `coh.storage/v1` envelope now recognizes metadata kind `memory`.
`memory` is the only new kind permitted to omit `case_id` in addition to the
existing catalog kinds, because analyst and organization namespaces are
intentionally not case-owned. Organization and tenant UUIDv7 identities remain
mandatory. Existing SQLite and PostgreSQL tables require no physical DDL
change because kind and nullable case identity are already generic columns.

Pre-release deployment order:

1. deploy readers that understand and default-deny `memory` records;
2. deploy the four repository-store instances and controller;
3. enable writes per namespace; and
4. retain the old binary until new writes have been backed up and verified.

Rollback disables new writes first. A prior binary will not resolve the new
kind and therefore fails closed. Durable memory rows and receipts are retained
for forward recovery; they are not rewritten into evidence, case, model, or
skill records.

## Verification

`scripts/verify_memory_namespaces.sh` runs contract, controller, boundary,
agent-loop, SQLite restart, repeated, race, and vet checks. The full CI baseline
then supplies architecture, dependency, secret, license, size, and complete Go
suite evidence.
