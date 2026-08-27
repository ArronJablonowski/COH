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

The guarded metadata adapter also uses strict internal pending-publication and
reference-marker envelopes. They contain only case scope, stable plaintext
identity, classification, encryption-context/locator digests, timestamps, and
receipt digests. They never contain raw evidence, manifest plaintext, source
identity, wrapped keys, or key references. Pending identities are recorded
before filesystem publication; receipt and reference-marker creation deletes
them in the same SQLite/PostgreSQL metadata transaction.

The v1 encryption reader requires the exact recorded wrapping-key reference
and revision. Operational rotation retains prior decrypt-only revisions;
in-place rewrap is not part of this contract. Key loss and decrypt failure are
availability failures and cannot yield a valid reference or plaintext result.
Rollback disables the writer while retaining the v1 reader, receipts,
reference markers, pending identities, ciphertexts, and required key revisions.

Transport is an attested input to this workflow rather than a socket exposed by
it. In-process callers bind the configured local channel; remote callers must
arrive through the deployment profile's mTLS boundary. The verifier and policy
decision bind the peer and channel digests before source bytes are consumed.
