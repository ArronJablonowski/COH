# COH signed evidence lifecycle contract v1

| Field | Value |
|---|---|
| Issue | COH-E10-05 / CYB-77 |
| Requirements | FR-028, FR-029, SEC-037, SEC-042 |
| Contract | `1.0.0` |
| Schema | `evidence-lifecycle.schema.json` |

The root schema closes eleven public payloads: command, canonical export
manifest, detached signature, package header, import verification report,
authorization request, decision, durable progress, disposition attestation,
completed record, and immutable receipt. Every object rejects additional
properties. Versions, operations, phases, outcomes, reasons, algorithms,
compression, classifications, roles, media types, and disposition mechanisms
are closed values.

One metadata-only command shape covers export, import, hold placement/release,
and deletion. Operation-specific values are always present and explicitly null
when inapplicable; semantic validation rejects every illegal combination. The
command binds exact scope, actor revision, artifact/package/source, purpose,
destination, reason, approval, policy, case revision, custody head, positive
resource limits, idempotency identity, and deadline.

V1 package framing is pathless and forward-only. The header requires the
`COHEVPKG1` magic, exact frame lengths and count, bounded total length, and
`compression: none`. It cannot express filenames, paths, directories, links,
devices, sparse files, nested packages, or extension metadata. The manifest
and signature frames precede raw artifact frames in manifest order. Unknown,
duplicate, reordered, trailing, truncated, archive-typed, compressed, or
oversized input is invalid.

The canonical manifest binds the case and classification; exporter and release
purpose/destination digests; every artifact, encrypted manifest, source/derived
role, parent edge, completed redaction receipt, and mapping digest; policy,
model, tool, query, and transformation versions; policy/approval/revocation;
complete custody proof; signed audit checkpoint; Ed25519 key identity/revision;
resource limits, validity, idempotency, and provenance. Its detached signature
is a separate strict payload over the exact canonical manifest digest.

An import verification report records the untrusted source/package identity,
header and signature, trusted key and revocation snapshot, artifact set,
lineage, components, custody, audit checkpoint, bounded outcome/reason, and
report digest. `valid` means all checks completed against the named trust
snapshot. `incomplete` is never sufficient for import or release authority.

Authority decisions repeat the exact operation, scope, actor, artifact/package,
policy, approval, custody head, revocation, and validity binding. Signature or
foreign authorization never implies a local allow decision. Exact replay needs
fresh authority where the operation can still have a consequence.

Progress is monotonic and operation-specific. Nullable digests make incomplete
phases explicit, while per-artifact progress supports exact multi-artifact
import recovery. A final record and receipt are immutable. Changed idempotency
reuse, phase skip/regression, or adoption of another package/artifact set is
denied.

Disposition attestation is distinct from the case tombstone and custody
authorization. It binds the exact authorized artifact set, lifecycle and
custody receipts, closed disposition mechanism, ordered encrypted objects,
key revisions, per-object verified outcomes, time, and canonical digest. Only
`removed` and same-intent `already_absent` are V1 success outcomes. It cannot
delete or claim deletion of lifecycle, custody, audit, signature, or provenance
history.

Readers and writers require exact schema and contract versions. Unknown,
missing, duplicate, non-canonical, malformed, excessive, or semantically
inconsistent input fails closed. Rollback retains V1 readers, records,
receipts, progress, public verification keys and revocation history, case
tombstones, custody/audit proof, packages in quarantine, and disposition
attestations while disabling new consequential operations.
