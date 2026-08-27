# OCSF-first normalized event envelope

Status: design frozen for CYB-80 Task 1

| Field | Value |
|---|---|
| Issue | COH-E11-01 / CYB-80 |
| Requirements | FR-021, FR-022 |
| Envelope | `coh.normalized-event-envelope/v1` |
| Contract | `1.0.0` |
| Canonical encoding | `COH-NJ-1` |
| OCSF target | `1.9.0` at `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba` |
| ECS target | `9.5.0` at `401807e0547301525acd28c4fb667203fec66d59` |

The envelope makes OCSF the normalized event body without replacing source
truth. Every accepted envelope retains a case-scoped immutable raw-evidence
reference, a canonical copy of the original vendor fields, an optional
canonical ECS projection, the exact normalization inputs, and enough lineage
to reproduce or reject the transformation. OCSF and ECS releases are pinned in
[`compatibility-targets.json`](../../contracts/normalization/v1/compatibility-targets.json);
development branches and floating version labels are not compatible targets.

## Requirement and invariant matrix

| Requirement | Contract invariant | Failure behavior |
|---|---|---|
| FR-021: OCSF-first normalized events | `ocsf.event` is required and binds OCSF version, release commit, class/category/type/activity identifiers, canonical event bytes, and digest. | Missing, unsupported, malformed, non-canonical, or digest-mismatched OCSF data is denied. |
| FR-021: preserve original vendor/ECS fields | `original.fields` is required. `ecs.fields` is explicit, canonical, and nullable only when no ECS projection was produced. Each section carries its own digest. | Field loss, changed bytes, unsupported version, or a false empty mapping is denied. Unmapped vendor fields remain in `original.fields`. |
| FR-021: preserve raw evidence references | `lineage.raw_artifact`, `raw_manifest_digest`, and `ingest_receipt_digest` bind the COH-E10 immutable ingestion result and exact case scope. | Missing, cross-case, digest/length/classification-mismatched, or unresolved references fail closed. Raw bytes are never embedded in the envelope. |
| FR-021: source, classification, and schema version | The envelope requires organization, tenant, case, source identity/digest, classification, collection time, envelope version, mapping-set digest, and normalizer component identity. | Missing scope, source, classification, or version is invalid input. Classification may not be weaker than the raw artifact classification. |
| FR-021: lineage and reproducibility | Parent envelope digests are a sorted set. Mapping, component, OCSF target, ECS target, raw manifest, and ingest receipt digests are immutable inputs. | Unsorted/duplicate parents, changed replay, or lineage substitution is denied. |
| FR-022: partitioned Parquet collections | A nullable dataset locator may bind a partitioned Parquet artifact, partition keys, row group/index, dataset schema digest, and bounded access profile. | Direct path/URL access, missing bounds, non-Parquet format, or out-of-range positions are denied. |
| FR-022: bounded Go dataset access only | The public package exposes only a context-aware `DatasetReader` port with explicit row, byte, page, and duration limits. It carries opaque artifact identity, never filesystem paths, SQL, HTTP, or connector handles. | Cancellation, timeout, limit exhaustion, incomplete reads, and unavailable storage return typed non-success outcomes; they never yield a complete result. |

## Field ownership

The raw artifact and manifest are owned by COH-E10. The normalization envelope
can reference but cannot mutate, replace, delete, decrypt, or authorize access
to those records. An authorized resolver must independently verify the
artifact digest, positive length, media type, classification, organization,
tenant, case, manifest digest, receipt digest, and provenance before returning
bytes.

`original.fields` is the canonical structured representation observed at the
source boundary. It is not reconstructed from OCSF or ECS. When the source is
not structured, it is an explicit bounded metadata object describing the raw
record while the immutable raw artifact remains authoritative. Values that do
not map to OCSF or ECS remain present here and are named in the normalization
coverage record; they are never silently discarded.

`ocsf.event` is the primary normalized body. The envelope validates the closed
COH base fields and the exact pinned upstream schema target. Source-specific
mapping logic belongs to the signed registry introduced by COH-E11-03, not to
this contract.

`ecs.fields` preserves an ECS projection when one was produced. It never
claims that arbitrary vendor fields are ECS fields. A null ECS projection is
distinct from an empty projection, and both retain the full original fields.

## Canonical and digest rules

All JSON is decoded with a 1 MiB document bound, duplicate-key detection,
64-level nesting bound, UTF-8 validation, and trailing-data rejection.
`COH-NJ-1` retains the repository's `COH-CJ-1` object, string, array, and
integer rules and adds exact fixed-decimal values for OCSF, ECS, and vendor
fields. Decimal exponents, negative zero, leading integer zeroes, and trailing
fractional zeroes are denied, giving every accepted number one lossless byte
representation. Object keys are sorted by Unicode code-point order, array
order is preserved, and no insignificant whitespace is emitted. Digests use
`sha256:<lowercase hex>` over those bytes.

Schema-declared sets are sorted and duplicate-free. Sequences—including source
arrays and any OCSF/ECS array—retain their observed order. Arbitrary original,
OCSF, and ECS objects are bounded by field count, depth, string length, and
canonical byte size before their digests are accepted.

The envelope digest is computed outside the envelope over its complete
canonical bytes. Nested section digests cover only the canonical value named
by that section, avoiding a self-referential digest.

## Compatibility and migration boundary

Envelope `v1` readers accept only contract `1.0.x` records whose compatibility
target manifest exactly matches the pinned OCSF and ECS release identities.
Additive upstream changes are not automatically compatible. Any target change
requires a new compatibility decision, replay of the positive and negative
fixture corpora, migration impact assessment, and a new target-manifest
digest. Existing envelopes retain their original target identities and remain
readable; they are never rewritten in place merely because a newer upstream
schema exists.

Rollback disables new writes using the rejected target while preserving the
reader, immutable evidence, envelopes, mapping sets, manifests, receipts, and
dataset artifacts required to reproduce prior outputs. Rollback never
relabels an event, drops a vendor field, weakens classification, or claims a
successful conversion that was not recorded.

## Privacy and security boundary

The envelope may contain sensitive event metadata and inherits at least the
raw artifact classification. It contains no credentials, key material,
authorization grants, policy source, raw evidence bytes, storage paths, URLs,
network clients, generic callbacks, shell, connector, or executor surface.
Logging and errors expose bounded reason codes and opaque digests rather than
event values.

## Task 1 design-freeze decision

The frozen contract direction is:

1. Pin OCSF `1.9.0` and ECS `9.5.0` by release tag, full commit, and downloaded
   source-archive SHA-256.
2. Make recoverable COH-E10 raw evidence and original vendor fields mandatory.
3. Keep OCSF primary, ECS explicit, and unmapped vendor values visible.
4. Bind every transformation to exact case, mapping, component, and upstream
   schema identities.
5. Represent Parquet only by immutable artifact identity and bounded logical
   location; permit access only through the narrow dataset port.

Unresolved blocking design findings: none.
