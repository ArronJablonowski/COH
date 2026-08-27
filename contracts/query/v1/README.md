# Query connector contract v1

| Field | Value |
|---|---|
| Issue | COH-E12-01 / CYB-85 |
| Requirements | FR-045, FR-054 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Digest | Domain-separated SHA-256 |

The contract is the only vendor-neutral boundary for read-only source queries.
It covers capability discovery, schemas, query validation, execution, polling,
paging, cancellation, typed limits, completeness, statistics, and opaque
adapter-held handles. It has no generic HTTP, header, credential, vendor-token,
mutation, or untyped options surface.

Every admitted capability snapshot asserts `read_only: true`; a snapshot that
does not make that assertion fails closed before any query is validated.

`query-connector.schema.json` is a JSON Schema draft 2020-12 bundle for every
published lifecycle record. Readers additionally apply the Go semantic
validator: exact versions, COH-CJ-1 unique-key decoding, UUIDv7 identities,
nanosecond UTC timestamps, sorted unique sets, half-open time ordering, nonzero
limits, result consistency, and domain-separated digests.

The canonical query fixture is the stable positive example. The denial corpus
names each fail-closed mutation used by contract tests. No fixture grants
authority; authorization, policy-decision, and audit-reservation digests must
all be supplied by the trusted COH-E05 boundary.

The Go SPI accepts and returns validated immutable document wrappers. Before
execution, `AdmitExecution` requires an accepted validation record bound to the
exact query ID and domain-separated canonical query digest. Denied, stale, or
substituted validator output cannot reach an adapter through the admitted path.

See `compatibility-matrix.md` for version, migration, recovery, and rollback
behavior.
