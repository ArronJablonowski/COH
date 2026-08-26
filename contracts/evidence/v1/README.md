# COH immutable CAS ingestion contract v1

| Field | Value |
|---|---|
| Issue | COH-E10-02 / CYB-71 |
| Requirements | FR-019, FR-020, NFR-011, EVAL-012, SEC-023 |
| Contract | `1.0.0` |
| Schema | `immutable-cas-ingestion.schema.json` |

The schema closes ingestion commands, authorization requests and decisions,
artifact manifests, encrypted-object metadata, immutable receipts, and all
status/source/component/transport/time values. Additional properties are
rejected at every object boundary. Optional source time and range values are
explicit JSON `null`.

Artifact identity always means the expected and independently verified
plaintext SHA-256 plus positive byte length. The encrypted-object record binds
that identity to chunked authenticated encryption, ciphertext facts, exact
case scope, configured key reference and revision, and an opaque locator
digest. A receipt uses the reduced `published_object` shape so key references
and wrapped-key metadata remain inside the encrypted CAS rather than SQL.

`ArtifactManifest` carries the required source, collection/source time,
optional half-open source range, transformation lineage, and closed tool,
query, and model version records. Manifest plaintext is itself ingested as an
encrypted CAS object. SQL metadata retains only immutable artifact, manifest,
authorization, audit, transport, idempotency, and provenance digests.

Raw evidence has no JSON field. It is supplied exactly once as a bounded stream
after validation, transport verification, and authorization. The contract has
no policy source, credential value, raw key, path, URL, HTTP, shell, connector,
executor, callback, or arbitrary metadata map.
