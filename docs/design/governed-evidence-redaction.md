# Governed evidence redaction

| Field | Value |
|---|---|
| Issue | COH-E10-04 / CYB-78 |
| Requirements | FR-030, SEC-036 |
| Source of truth | Immutable encrypted CAS ingestion (CYB-71) |
| Custody boundary | Append-only chain of custody (CYB-79) |
| Approval boundary | Exact approval fingerprint and lifecycle (CYB-50/CYB-51) |
| Status | Implemented and verified |

## Purpose and trust boundary

Governed redaction creates a new immutable derived artifact while retaining the
exact source artifact and encrypted manifest. The result proves the requesting
actor and revision, case, source, rule and revision, reason, approved plan,
source-to-derived mapping, output facts, policy and revocation state, custody
lineage, audit evidence, and time. Redaction never edits, relabels, replaces, or
deletes the source.

The workflow is not a general content-processing API. A model, provider,
connector, executor, policy engine, approval record, or controller cannot read
plaintext or supply executable selectors. Only the trusted derivation adapter
may decrypt source bytes. It receives one closed plan and can emit only a
deterministically transformed stream plus a canonical mapping. It has no
authority, approval, custody, audit, release, network, shell, or arbitrary
filesystem capability.

## Frozen decisions

1. V1 plans use sorted, unique, non-overlapping half-open byte ranges against
   the canonical source plaintext. Semantic selectors, regular expressions,
   scripts, prompts, callbacks, and model-generated executable rules are not
   part of the contract.
2. Each range binds its start/end, SHA-256 of the exact selected source bytes,
   and one closed replacement mode: `remove`, `mask`, or `token`. Replacement
   bytes are implementation-defined by the signed rule revision; they are not
   caller-provided content.
3. The plan binds a signed rule identity/revision/digest, reason digest,
   expected source artifact and manifest, output media type/classification,
   mapping-plan digest, policy digest, approval fingerprint, validity window,
   and maximum output size. The mapping-plan digest covers the expected spans
   and output intervals but not the not-yet-derived artifact digest. Any change
   requires a new plan, policy decision, and approval.
4. The canonical mapping records each source interval, selected-segment digest,
   output interval, replacement mode and digest, and the complete source,
   derived, plan, rule, approval, and provenance digests. Mapping plaintext is
   sensitive and is published as a separately encrypted case artifact. Public
   records carry only its immutable artifact/manifest references and digest.
5. Redaction is deterministic and two-pass. Pass one decrypt-verifies the
   immutable source, validates every range and selected-segment digest, applies
   the exact transformation while hashing/counting discarded output, and
   produces the canonical mapping. Pass two reopens and re-verifies the same
   immutable source and streams the identical transformation directly into
   immutable encrypted ingestion using the pass-one digest and length.
6. No unencrypted derived or mapping staging file is permitted. Bounded buffers
   are adapter-owned, overwritten after use, and never logged, audited,
   persisted in workflow history, or returned in an error.
7. Output is a new `derived` ingestion with the source artifact and manifest as
   its exact parent. The source remains independently resolvable under its
   existing authority. Deduplication may converge on an existing identical
   derived object but cannot alias or replace the source reference.
8. Immediately before authority and the first plaintext read, the approval
   boundary atomically authorizes one exact intent use. Its durable proof may
   show `granted` when uses remain or `consumed` when this exact use exhausted
   the approval. Exact replay recovers and verifies that same proof; an expired,
   unrelated consumed, revoked, changed, self, or cross-scope approval is denial.
9. The derived and mapping ingestion receipts may exist before custody, but no
   result or plaintext reference is released until a `redact/completed` custody
   record binds source parent, child, rule, reason, mapping, approval, policy,
   governing redaction decision, current case revision, and exact custody head
   and its audit proof verifies. The governing decision is distinct from a
   prior custody authorization receipt.
10. A final redaction receipt links the intent, plan, policy decision,
    approval, source, derived and mapping ingestion receipts, custody receipt,
    audit event, and provenance. Exact replay reauthorizes and returns only that
    receipt. Changed idempotency reuse is denied.

The final audit event binds a domain-separated redaction-record precommit that
omits the audit-event digest. The stored record and receipt then bind the exact
audit-event digest. This preserves both directions of the cross-reference
without a circular hash.

## Closed record set

| Record | Required safe facts | Explicit exclusion |
|---|---|---|
| `Command` | Request/idempotency, exact scope and actor revision, source reference, rule/approved-plan/reason, output and key profiles, policy, expected case/custody revisions, deadline | Ranges, plaintext, policy source, approval grant body |
| `Plan` | Exact source, sorted spans, rule revision/digest, mapping preimage digest, output profile/bounds, validity | Regex, script, prompt, callback, free-form replacement |
| `ApprovalUseProof` | Approval/fingerprint/manifest/policy/intent digests, resulting state/revision/use count, validity and exact use proof | Grant credentials, signatures, free-form comments |
| `AuthorizationRequest` | Command, plan, current case/source/custody facts, approval snapshot digest | Plaintext or mapping plaintext |
| `Decision` | Exact authorization digest, scope, actor, plan, policy/revocation, allow/deny, expiry | Policy source or implicit approval |
| `Mapping` | Source/output intervals and digests, complete source/derived/plan/approval/provenance bindings | Selected bytes or reversible originals |
| `Record` | Durable phase and every immutable receipt/custody/audit binding | Evidence bytes, raw rule material, storage locations |
| `Receipt` | Exact completed record and intent/idempotency digest | Mutable status or partial success |

All public JSON objects reject unknown or additional properties. Nullable fields
are explicit. Enums are closed and versioned. Canonical decoding rejects
duplicate keys, alternate number/time encodings, trailing values, invalid UTF-8,
oversized inputs, and non-canonical bytes.

## Narrow ports

| Port | Allowed operation | Forbidden surface |
|---|---|---|
| `Authority` | Decide one exact metadata-only authorization request | Policy source, plaintext, approval mutation |
| `ApprovalStore` | Atomically authorize/recover one idempotent exact intent use and verify its proof | Grant, revoke, generic query, approval reuse |
| `CaseStore` | Load minimum current case snapshot | Lifecycle mutation or generic storage |
| `PlanStore` | Resolve one signed/versioned closed plan by digest | Rule authoring, script execution, arbitrary selector |
| `Deriver` | Deterministically verify and transform one immutable source twice | Authority, network, shell, release, generic callback |
| `Publisher` | Ingest exact derived and mapping streams with declared digest/length/parents | Source deletion, mutable overwrite, arbitrary CAS access |
| `CustodyRecorder` | Append exact `redact/completed` command and return verified receipt | Chain rewrite, skipped head, release |
| `Store` | Recover intent and atomically advance bounded redaction phase/receipt | Generic query, update of completed history, delete |
| `Auditor` | Append deterministic redacted denial/final orchestration event | Plaintext, mapping content, mutable audit access |
| `Clock` | Return canonical UTC time | Timer callback or scheduler |

No port accepts `any`, a generic map, function, channel, filesystem path,
network client, HTTP request, command, executor, connector, provider, policy
engine, credential value, or raw approval material.

## Plan and mapping invariants

For source length `N`, every plan span satisfies `0 <= start < end <= N`.
Spans are sorted by `start`, never overlap or touch ambiguously, and the count
and total selected bytes are bounded. Each selected segment must hash to the
plan's exact digest during both passes. An empty plan is denied.

`remove` emits no bytes. `mask` emits the signed rule revision's digest-bound,
deterministic same-length mask and is valid only for media profiles that define
it. `token`
emits the signed rule revision's fixed token. A format-aware rule profile must
validate the complete derived output before publication; byte-range validity
alone does not prove that JSON, archive, image, or other structured media is
safe or well formed. Unsupported media/rule combinations are denied, not
silently treated as opaque bytes.

The mapping is computed from the plan and observed pass-one output. It is
canonical, sorted, complete, and one-to-one with plan spans. It never stores the
removed bytes. Its classification is at least the source classification and
may be raised by policy because offsets and segment digests are linkable.
Mapping access is a separate governed custody operation and is never implied by
permission to access the redacted artifact.

## Rule governance and mapping access

Rule publishers control the closed media profiles, replacement modes and
digest-bound mask/token material. A deployment admits a rule only after its
signature, signer revision and revocation state verify through the trusted rule
resolver. Rotation installs the new verify-capable signer and rule revision
before writers use it; historical verify-only keys and rule material remain for
the full evidence-retention period. Revocation prevents new plans and cannot
rewrite an existing receipt or silently substitute replacement material.

Mapping authorization is independent of derived-artifact authorization. The
encrypted mapping reference, classification and digest may be disclosed only
through a separately approved case-scoped access/custody operation. Operators,
exports and downstream workflows cannot infer access merely because they hold
the redacted artifact or its receipt. Backup, retention, legal hold and key
recovery treat mapping objects as at least as sensitive as their source.

## State and release ordering

| Phase | Durable/observable effect | Recovery behavior |
|---|---|---|
| `validated` | Command, scope, deadline, expected revisions checked | No plaintext or durable result |
| `planned` | Exact plan, approval snapshot, authority decision bound | Changed replay denied; expired state reauthorized |
| `derived` | Pass one yields output and mapping digests in memory | No public reference; safe to repeat from immutable source |
| `published` | Derived and encrypted mapping receipts durably exist | References withheld; replay resolves and verifies both |
| `custodied` | `redact/completed` lineage record and custody audit verify | No duplicate custody append; final audit may be repaired |
| `completed` | Final record/receipt commits, deterministic redaction audit appends and verifies | Audit failure withholds success; replay repairs the same event and returns the exact receipt |

The guarded store atomically commits each phase with an expected revision and
immutable phase evidence. It never claims one transaction spans CAS, custody,
audit, and metadata. Instead, every external side effect is content-addressed
and replay-safe, and the state machine moves forward only after independently
verifying the effect. A crash at any boundary leaves either no effect or a
recoverable, non-released artifact/receipt.

## Failure and adversarial matrix

| Boundary or fault | Required result |
|---|---|
| Malformed command/plan, unknown field, invalid enum or non-canonical input | Invalid before authority, approval, plaintext, publication, or custody |
| Missing, cross-tenant/case, corrupt, or changed source/manifest/receipt | Safe denial; no existence oracle or derived release |
| Empty, out-of-range, overlapping, unsorted, duplicate, excessive, or zero-length span | Denial before plaintext transformation |
| Selected-segment digest mismatch in either pass | Integrity denial; no derived reference |
| Non-deterministic pass, output digest/length drift, invalid format | Quarantine candidate; no ingestion receipt or release |
| Missing, self, stale, consumed, expired, rejected, or revoked approval | Denial before plaintext; bounded audit reason |
| Stale actor, case, custody head, rule, policy, or revocation | No publication/custody under old decision |
| Derived or mapping publication failure/lost response | Resolve exact content-addressed receipt or remain unreleased |
| Custody conflict/failure after publication | Published objects remain unreferenced by redaction result; reload and reauthorize |
| Audit failure after custody | Success withheld; replay verifies same custody record and repairs audit |
| Exact concurrent replay | One final receipt and custody link; all callers converge after fresh authority |
| Changed concurrent request | One phase/head winner; loser is denied or conflicts and must replan |
| Cancellation/deadline at either pass or external boundary | Prompt stop, buffer clearing, no partial usable result |
| Crash/restart at every phase | Resume from verified durable evidence without duplicate or skipped phase |
| Source retention attack or attempted overwrite/delete | Interface denial; original artifact/manifest/receipt remain resolvable |
| Mapping insertion/deletion/reorder/mutation or substituted derived artifact | Verification fails; no completed receipt |

## Audit and privacy

Denied attempts append a deterministic tenant event containing only command,
scope, actor, plan/rule/policy/approval digests, bounded reason, and time. The
successful custody event proves evidence lineage. A final redaction event binds
the custody receipt and completed redaction receipt. Audit events never contain
source, derived, or mapping bytes, selected text, offsets, replacement text,
raw reasons, grant identities beyond approved actor identifiers, or backend
errors.

Artifact and mapping digests, lengths, classifications, timestamps, span counts,
and rule/approval identifiers are sensitive metadata. They inherit case access,
retention, backup, and audit controls. Low-entropy reason and rule inputs are
domain-separated and nonce-bound before crossing the workflow boundary.

## Migration, rollback, and ownership

V1 adds a validated `redaction_record` metadata kind to the existing guarded
repository and new strict contract readers before enabling writers. It requires
no SQL DDL. Deployment must also install the derivation rule revision, mapping
encryption profile, source reader, ingestion publisher, custody adapter, and
approval resolver before the feature is enabled. Unknown versions fail closed.

Rollback disables new redaction and result release while retaining the V1
reader, redaction phases/receipts, source and derived CAS objects, encrypted
mapping, ingestion receipts, custody records, audit history, and required key
and rule revisions for forward recovery. Rollback never deletes or rewrites the
source, advertises an uncustodied derivative, or lowers classification.

CYB-78 owns plan, deterministic transformation, encrypted mapping, and
orchestration semantics. CYB-71 remains the only immutable publication owner;
CYB-79 remains the custody/lineage owner; CYB-50/CYB-51 remain approval owners;
CYB-77 consumes completed redaction receipts for signed export and deletion but
cannot reinterpret or weaken them.

Downstream release therefore requires an exact valid completed receipt, its
matching durable record, verified custody receipt and verified redaction audit
event. A derived CAS reference alone, a progress record, an ingestion receipt,
or mapping possession is never release authority. CYB-77 may package the
completed derived artifact but must preserve the source lineage and cannot use
that permission to disclose the mapping, delete the source, bypass retention or
manufacture completion after rollback.

## Requirement trace

| Requirement | Implemented evidence |
|---|---|
| FR-030 | Every redaction yields a new immutable derived artifact and encrypted mapping bound to exact rule, reason, actor, source, approval, custody, audit, and provenance while retaining the source. |
| SEC-036 | Redaction is a default-deny approved transformation with no in-place mutation, implicit authority, plaintext metadata leakage, uncustodied release, or unverifiable mapping. |

No unresolved implementation or release-order decision remains for V1.
