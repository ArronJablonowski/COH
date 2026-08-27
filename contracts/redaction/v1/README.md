# COH governed evidence redaction contract v1

| Field | Value |
|---|---|
| Issue | COH-E10-04 / CYB-78 |
| Requirements | FR-030, SEC-036 |
| Contract | `1.0.0` |
| Schema | `governed-redaction.schema.json` |

The root schema closes eight public records: command, signed rule set, approved
plan, source-to-derived mapping, authorization request, decision, completed
record, and immutable receipt. Every object rejects additional properties and
all operations use closed version, outcome, reason, classification, replacement,
approval-state, and time values.

The command is metadata-only. It binds exact organization, tenant, case, actor
revision, immutable source artifact and encrypted manifest, signed rule digest,
reason digest, output profile, key profile, policy, expected case revision,
expected custody head, idempotency identity, and deadline. It has no span list,
selected text, replacement value, policy source, or approval grant body.

An approved plan carries one or more sorted half-open byte spans. Each span
binds the exact selected source-segment digest, one of `remove`, `mask`, or
`token`, and the expected output interval. The plan binds the signed rule
revision, mapping-plan digest, output bounds, exact approval fingerprint,
approval manifest, positive policy decision, policy digest, and validity window.
Go semantic validation additionally rejects empty, overlapping, unsorted,
touching-ambiguous, out-of-range, excessive, and output-inconsistent spans.

The signed rule set limits media types, permitted replacement modes, span and
byte ceilings, output size, signer key revision, and optional fixed-token
digest. Signature verification and key-revocation checks occur in the trusted
rule resolver. There is no regex, selector language, script, prompt, callback,
caller replacement content, or extension map.

Mapping plaintext is a separately encrypted case artifact. It records only
offsets, source-segment and replacement digests, replacement modes, immutable
source/derived facts, exact plan/rule/reason/approval bindings, time, and
provenance. It never contains selected source bytes, removed values, or a
reversible copy. Its public reference and digest remain safe metadata but still
inherit the source case's access, classification, retention, and audit policy.

The authorization request binds the current case, independently verified
source, exact approved plan and approval snapshot, and current custody head.
The decision repeats the exact scope, actor, source, plan, approval, policy,
revocation, case revision, head, validity, and bounded allow/deny reason. A
decision cannot be reused after any bound fact changes.

The completed record links derived and mapping ingestion receipts to one exact
`redact/completed` custody receipt and deterministic audit event. Its provenance
chains from the immutable source. The final receipt is the only releasable
result and supports exact lost-response recovery without duplicate publication
or custody append. Partial phase state is internal, strict, and never a success.

Readers and writers require exact schema and contract versions. Unknown,
missing, duplicate, trailing, malformed, oversized, or non-canonical input
fails closed. Rollback retains V1 readers, records, receipts, sources, derived
objects, encrypted mappings, custody, audit, and historical rule/key revisions
while disabling new redaction and result release.
