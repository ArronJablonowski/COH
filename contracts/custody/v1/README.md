# COH chain-of-custody contract v1

| Field | Value |
|---|---|
| Issue | COH-E10-03 / CYB-79 |
| Requirements | FR-020, FR-023, SEC-020, EVAL-013 |
| Contract | `1.0.0` |
| Schema | `chain-of-custody.schema.json` |

The schema closes custody commands, authorization requests and decisions,
append-only records, immutable receipts, verification reports, and every
operation, phase, outcome, and reason value. Additional properties are rejected
at every object boundary. Optional operation facts are required as explicit
JSON values and use `null` when absent; there are no extension maps.

The case-scoped chain supports acquisition, access, transformation, redaction,
transfer, export, hold placement/release, deletion authorization, and completed
deletion. JSON Schema conditionals require the core operation-specific facts.
Go validation additionally rejects irrelevant non-null fields, unordered or
duplicate parent sets, invalid operation/phase combinations, and inconsistent
authorization/completion ancestry.

An `evidence_reference` binds the immutable artifact, encrypted manifest,
manifest provenance, and ingestion receipt. It contains no evidence bytes or
manifest plaintext. Parent references form the transformation-lineage graph;
the case custody sequence independently orders evidence handling events.

The command binds an expected case revision and exact custody head. The
authorization request adds verified evidence facts and the fresh lifecycle
snapshot. The decision repeats the complete actor, case, operation, policy, and
head binding with current revocation state. A stale or changed binding cannot
be committed under an earlier decision.

Every record embeds its complete safe command, exact prior chain hash, authority
and evidence-verification digests, provenance, deterministic audit-event digest,
record digest, and new chain hash. The chain head, record, and receipt commit in
one storage transaction. The receipt permits lost-response recovery without a
second append.

Custody records do not duplicate signatures. Their deterministic audit event is
appended to the existing tenant audit chain, whose signed checkpoint provides
the external trust anchor. A verification report names that checkpoint when
one covers the requested interval. A report without a covering checkpoint is
explicitly incomplete and cannot be presented as independently verified.

The contract has no field for raw evidence, manifest content, source or
destination text, recipient identity, policy source, approval material,
credentials, keys, filesystem paths, URLs, network clients, executors, shell
commands, callbacks, or free-form reasons. Sensitive values are represented by
domain-separated digests computed before this boundary.
