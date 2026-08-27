# Immutable CAS ingestion

| Field | Value |
|---|---|
| Issue | COH-E10-02 / CYB-71 |
| Requirements | FR-019, FR-020, NFR-011, EVAL-012, SEC-023 |
| Data | Raw and derived security evidence plus sensitive provenance metadata |
| Status | Implemented; verification pending final evidence capture |

## Purpose and boundary

The ingestion boundary accepts one authorized, bounded byte stream and creates
an immutable SHA-256 artifact reference only after the complete plaintext,
encrypted object, and versioned manifest have been verified. A caller receives
either a reference to a complete object and manifest or no reference. A staged
file, encrypted orphan, partial metadata transaction, key error, or ambiguous
response is never treated as published evidence.

Ingestion is case-scoped. Every request binds organization, tenant, case,
actor and actor revision, expected plaintext digest and length, media type,
classification, source/provenance input, policy digest, key profile, transport
channel, idempotency key, and deadline. Missing, malformed, cross-scope, stale,
or changed identity is rejected before source bytes are read.

The controller never receives policy source, credentials, raw encryption keys,
connectors, executors, shell, HTTP clients, paths, or generic callbacks. Raw
bytes are consumed through one bounded, cancellation-aware, forward-only
`Source`; they are never serialized
into workflow history, audit, receipts, SQL metadata, logs, or errors.

## Published records

The v1 contract defines closed records for:

- `IngestCommand`: exact identity, expected artifact facts, provenance input,
  transport binding, policy/key-profile digests, idempotency, and deadline;
- `AuthorizationRequest` and `Decision`: exact current case state and every
  command binding with current revocation and expiry;
- `ArtifactManifest`: source, collection and source times, optional half-open
  time range, transformation lineage, and closed tool/query/model versions;
- `EncryptedObject`: plaintext and ciphertext digests and lengths, chunked
  format version, key reference/revision, wrapped-key digest, authenticated
  context digest, and immutable case-scoped locator digest;
- `Receipt`: command, artifact and encrypted-manifest references, authority,
  audit, idempotency, and provenance bindings; and
- closed status values `staged`, `verified`, and `published`. Only `published`
  may be returned as an `ArtifactRef`.

Optional times and component versions use explicit JSON `null` or empty closed
arrays as defined by schema. There are no arbitrary metadata maps. Source
values that may reveal sensitive infrastructure exist only inside the
encrypted manifest object; durable SQL state carries their canonical digest.

## Narrow ports

| Port | Allowed surface | Explicit exclusion |
|---|---|---|
| `Authority` | authorize exact metadata-only request | policy source, approval token, credential, evaluator handle |
| `TransportVerifier` | validate in-process or mTLS channel binding | socket, certificate private key, listener, HTTP client |
| `CaseStore` | load the minimum current lifecycle snapshot | lifecycle mutation, retention mutation, generic repository access |
| `EncryptedCAS` | stage, verify, plan, publish, resolve/find verified objects, list stale stages, abandon a stage | raw key material, filesystem path, arbitrary delete |
| `ManifestStore` | track/recover pending identities, recover/commit receipts, prove committed references | evidence bytes, source metadata plaintext, physical CAS mutation |
| `Auditor` | append bounded tamper-evident event | evidence or manifest content |
| `Clock` | current UTC time | timer callback or scheduler |

The concrete encrypted-CAS adapter owns a narrower internal `KeyManager` that
creates or unwraps a data key for an exact key-profile and authenticated scope.
Raw data keys never cross into the workflow/controller package and are cleared
after use. Public records contain only opaque key references, positive
revisions, algorithms, and digests of wrapped material.

## Ingestion state and ordering

| Step | Durable state | Failure result |
|---|---|---|
| validate command, channel, case state, and fresh authority | none | typed denial; source unread |
| create hidden case-scoped stage and data key | incomplete stage only | stage removed or later swept; no reference |
| stream, hash, and chunk-encrypt expected plaintext bytes | encrypted incomplete stage | close, zero key, remove/sweep; no reference |
| fsync, reopen, decrypt, and verify plaintext/ciphertext facts | verified encrypted stage | quarantine/remove; no reference |
| durably track stable planned artifact identity | pending SQL identity; no resolvable reference | restart classifies missing/staged state without guessing |
| atomically link at case-scoped SHA-256 location and fsync directory | complete encrypted object, possibly orphaned | exact replay/reconciliation; no reference yet |
| construct, track, and publish encrypted canonical manifest | complete artifact plus manifest, pending SQL identities | exact replay/reconciliation; no reference yet |
| atomically commit immutable receipt and both reference markers while deleting pending identities | resolvable reference | recover exact commit; changed replay denied |
| append deterministic audit event | committed reference, success withheld | exact replay republishes audit before release |
| return `ArtifactRef` and manifest reference | published | success |

CAS publication precedes SQL reference publication because filesystem linking
and database commit cannot share a transaction. This ordering permits an
unreferenced encrypted orphan but never a dangling reference. Staging and
orphan reconciliation classifies only stale hidden stages or decrypt-verified
objects with a durable pending identity and no committed reference marker.
The v1 surface provides no deletion operation, so classification cannot delete
a referenced digest or turn missing metadata into destructive proof.

## Streaming and immutable identity

The command requires an expected `sha256:<hex>` and positive length no greater
than the configured bound. The controller authorizes metadata before reading.
The adapter reads the source once in bounded chunks, rejects an early EOF,
extra byte, short write, read error, cancellation, or deadline, and computes
the plaintext SHA-256 while encrypting. Neither the source nor a chunk is
retained after its successor has been processed.

The immutable address is the verified plaintext SHA-256, namespaced by exact
organization, tenant, and case. This prevents global-deduplication existence
leaks and prevents ciphertext authenticated for one case being reused in
another. An existing address is accepted as deduplication only after the
adapter decrypts it under current authority and proves exact plaintext digest,
length, media type, classification, key context, and format. A conflict or
corrupt existing object fails closed; it is never overwritten.

Retrieval first authorizes and loads the exact committed manifest reference,
then resolves through `EncryptedCAS.Resolve`. The adapter authenticates every
frame, unwraps only the bound key revision, and recomputes plaintext digest and
length through EOF. A missing key, revoked key, unwrap/decrypt error, changed
header/frame/footer, truncated stream, or digest/length mismatch yields no
plaintext success and no valid reference claim.

## Encryption format and key handling

At-rest objects use a versioned chunked AEAD envelope. V1 uses AES-256-GCM with
a fresh random data-encryption key and nonce prefix per staged object. Each
bounded data frame and the distinct terminal footer have a monotonic counter.
Additional authenticated data contains the canonical header digest, frame
type, and counter; that header binds format version, hashed case scope,
expected plaintext digest and length, media type, classification, key profile,
wrapped-key digest, and encryption-context digest. The encrypted authenticated
footer repeats the complete plaintext digest, length, and frame count. The
published object and receipt bind the independently computed full ciphertext
digest and length.

The data key is wrapped by a configured operator- or platform-managed key. Key
reference, revision, algorithm, and wrapped bytes are stored in the encrypted
object header; sensitive provenance stays in the separately encrypted manifest.
The wrapping key is never persisted by COH metadata. V1 reads the exact key
reference and revision recorded in the envelope and does not perform in-place
rewrapping. Rotation therefore retains old decrypt-only key revisions until a
separate, verified immutable-envelope migration exists. Key loss makes the
artifact unavailable and auditable; it cannot produce a false-success read or
plaintext result.

Plaintext is allowed only in process memory. Temporary files, CAS objects,
manifests, backups, and failure artifacts are encrypted. The ingestion API
accepts an in-process stream or a transport-attested mTLS stream. Raw evidence
must not cross a plaintext Unix socket or HTTP connection. Deployment-profile
and transport gates remain responsible for certificate enrollment and TLS
configuration; the ingestion decision binds their channel-binding digest.

## Manifest and provenance

Every evidence object has one canonical encrypted `ArtifactManifest` binding:

- exact case and artifact digest, length, media type, and classification;
- source kind, stable source identity digest, source artifact digest when
  derived, and collection method/version;
- collection time, original source time with precision/uncertainty, and an
  optional half-open source range;
- ordered parent artifact and prior-manifest digests;
- closed tool, query, and model component identities with immutable version or
  digest; and
- actor, policy, authorization, revocation, transport, encryption-context,
  audit, prior-provenance, and provenance digests.

The receipt stores the encrypted manifest reference and complete canonical
digests, not manifest plaintext. Provenance chains from the source/parent
manifest set and exact ingestion command. The later custody leaf records
acquisition and access events; this leaf supplies its immutable acquisition
receipt and audit proof without pre-implementing the custody ledger.

## Replay, concurrency, and failures

An exact idempotency replay recovers the immutable receipt, validates the
artifact and manifest through the CAS, obtains current transport and policy
authority, repairs the deterministic audit append, and returns the original
reference. Reusing a key for a changed command is denied. Concurrent identical
ingestions may converge only after both verify the same published object;
concurrent changed metadata under one key conflicts. No code path silently
re-hashes a different stream, guesses whether publication occurred, or creates
a new receipt for an ambiguous prior request.

Fault injection covers source reads, random generation, key create/unwrap,
frame seal/open, stage write/sync/close/reopen, verify, rename, directory sync,
manifest publish, SQL commit, audit append, restart, concurrent deduplication,
and orphan reconciliation. At every point the observable outcome is a complete
digest-verified artifact plus manifest and receipt, or no resolvable reference.

## Migration and rollback

The generic guarded metadata repository uses the validated
`artifact_manifest` kind for pending publication identities, committed
reference markers, and immutable receipts; SQLite/PostgreSQL need no new table.
The filesystem adapter introduces a versioned encrypted-CAS root with private
`staging`, `objects`, and `quarantine` directories. Artifact and manifest
ciphertexts share the same case-scoped CAS format. Startup rejects unsafe
permissions, symlink roots, invalid chunk bounds, or a missing key manager
before accepting writes.

Cutover installs the v1 reader and key revision before enabling its writer.
Rollback disables new ingestion but retains the v1 reader, old decrypt-only
key revisions, receipts, reference markers, pending identities, and objects.
It never decrypts into a replacement plaintext store or deletes an
unknown/newer envelope. Reconciliation and exact replay resume idempotently
after restart.

## Requirement trace

| Requirement | Design evidence |
|---|---|
| FR-019 | One bounded stream is addressed by verified plaintext SHA-256; every read rechecks digest and length. |
| FR-020 | Each artifact has a strict encrypted versioned manifest containing source, time, lineage, and component versions. |
| NFR-011 | Publish-before-reference ordering and atomic receipt commit expose a complete verified artifact or no reference. |
| EVAL-012 | Every stream, crypto, filesystem, manifest, database, audit, and restart boundary has an explicit failure-injection outcome. |
| SEC-023 | Evidence and sensitive manifest metadata use chunked AEAD at rest; only in-process or mTLS-attested streams are accepted in transit. |
