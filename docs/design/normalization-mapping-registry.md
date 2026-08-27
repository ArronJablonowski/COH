# Normalization mapping registry design freeze

Status: frozen for implementation  
Stable key: COH-E11-03  
Linear: CYB-81  
Requirements: FR-021, FR-025  
Depends on: COH-E10, COH-E11-01 / CYB-80

## Purpose and boundary

The registry selects and verifies a source-specific, signed, versioned,
data-only mapping and applies it deterministically to canonical original event
fields. It produces candidate OCSF/ECS projections, explicit coverage and
unmapped paths, typed entity hints, reverse-validation results, and a
transformation identity for construction of a new CYB-80 normalized envelope.

A mapper never edits a validated CYB-80 envelope. The original canonical field
object and all COH-E10 artifact, manifest, receipt, provenance, case, source,
classification, and lineage bindings are carried unchanged into the new
envelope. The CYB-80 validator remains the authority for its complete envelope,
OCSF base fields, ECS state, target pins, classification, lineage, section
digests, and transformation digest.

This leaf does not merge entities or correlate events. Its FR-025 contribution
is limited to typed, evidence-bound identifier hints that CYB-83 may consume.

## Frozen compatibility bindings

| Existing contract | Retained input | Mapping-registry rule |
|---|---|---|
| COH-E10 immutable evidence | organization, tenant, case, artifact, manifest, ingest receipt, and source provenance identities | Verify the complete binding before mapping; never accept artifact digest alone or expose evidence bytes. |
| `coh.normalized-event-envelope/v1` | source kind/identity digest/method/version, canonical original fields/digest, classification, lineage, OCSF/ECS pins, mapping-set and transformation digests | Map the exact canonical original object; preserve it byte-for-byte. Produce candidate sections and mapping metadata, then pass a newly constructed envelope through the CYB-80 validator. |
| OCSF `1.9.0` / commit `856d462b…` | primary normalized target | A manifest binds the exact version, commit, and CYB-80 target-manifest digest. A target change requires a new mapping revision and corpus replay. |
| ECS `9.5.0` / commit `401807e0…` | optional preserving projection | Absence is explicit. A mapping cannot claim ECS coverage without an exact pinned target and declared rules. |
| CYB-83 entity resolution | typed identifier hints plus mapping/rule provenance | Hints contain type, canonical output path, rule ID, confidence ceiling, and source-field digest. They grant no merge, correlation, or authority. |

Unknown fields inside the bounded CYB-80 original object remain recoverable.
The registry determines their semantic handling but can never remove them.

## Source identity and registry selection

Each manifest carries one exact source matcher:

- source kind;
- product/vendor token and its digest;
- source schema name, version, and immutable digest;
- collection method and version; and
- optional exact source-identity digest when a mapping is installation-specific.

There are no wildcards, regular expressions, partial-product matches, fallback
vendors, or case-insensitive guesses. A request binds the complete matcher and
either an exact signed-manifest digest or an exact registry-current revision.
Zero matches is `mapping_not_found`; more than one is `mapping_ambiguous`.
Selection never silently falls back to an older, generic, or unsigned mapping.

The durable registry state binds `(organization, tenant, source matcher)` to a
current manifest digest, revision, predecessor digest, activation time, and
registry provenance head. Promotion is monotonic. Rollback moves the current
pointer only to the immediate verified predecessor and does not rewrite a
manifest or historical normalized event.

## Signed manifest

The canonical manifest binds:

- schema and contract versions, mapping ID, semantic version, revision, and
  predecessor digest;
- exact source matcher and OCSF/ECS compatibility targets;
- ordered mapping rules and their canonical digest;
- input inventory policy, ignored-field declarations, unmapped disposition,
  collision policy, and maximum rule/field/value limits;
- typed entity-hint declarations and confidence ceilings;
- issuer/publisher, creation time, not-before/not-after interval, and review
  identity; and
- revocation-list identity and minimum revision.

The signed envelope binds the manifest digest, publisher actor, public key ID
and revision, signature algorithm `ed25519`, and detached base64url signature.
The signature preimage is domain-separated:

`"COH-MAPPING-MANIFEST-V1\x00" || raw_sha256_manifest_digest`

Private keys never enter this package. The injected verifier confirms the
exact preimage, publisher/key/revision trust, validity interval, purpose, and
current revocation snapshot. Signature validity does not grant case access,
policy authority, or permission to rewrite evidence.

## Closed mapping language

Every rule has a unique stable rule ID, exact input path or typed constant,
exact output namespace/path, input/output type, operation, required/optional
state, reversibility state, loss state, and entity-hint metadata. Rule order is
part of the signed digest.

Allowed operations are:

| Operation | Behavior | Reverse state |
|---|---|---|
| `copy` | Copy one value without type change. | Reversible when the output is unique. |
| `constant` | Emit a signed typed literal. | Not reversible; no source field claimed. |
| `enum` | Map through a complete, closed table. | Reversible only when values are bijective. |
| `to_integer` | Accept a canonical base-10 integer string within a signed range. | Lossless only when the source lexical form is already canonical. |
| `to_string` | Render a supported scalar in one canonical representation. | Reversible only for the bound scalar type and range. |
| `timestamp_reference` | Bind a source path for CYB-82 processing; does not parse time. | Preserves source text; temporal reversibility belongs to CYB-82. |

Input paths are exact bounded JSON object paths rooted at `original`; output
paths are exact bounded paths rooted at `ocsf` or `ecs`. Array traversal,
wildcards, recursive descent, dynamic keys, interpolation, joins, arithmetic,
regular expressions, templating, scripts, WASM, SQL, CEL/Rego/JQ, generic
expressions, and callbacks are denied. The mapping language cannot invoke a
tool, connector, executor, network, filesystem, policy engine, or model.

Output paths are unique across all rules. Parent/child output collisions,
duplicate rule IDs, duplicate enum inputs, non-bijective rules declared
reversible, undeclared outputs, invalid target types, range overflow, and
canonicalization changes are denied. Required input absence denies the mapping;
optional absence is recorded as explicit unmapped state.

## Reversibility and loss

`reversible` means that the produced normalized scalar can be converted back to
the same canonical semantic source scalar through the signed reverse rule. It
does not mean raw evidence can be reconstructed or replaced. Original CYB-80
fields always remain authoritative and byte-recoverable.

Each applied rule records one of `reversible`, `lossless_not_reversible`, or
`lossy`, plus an exact reason. Enum mappings declared reversible must be
bijective. Constants are never reversible. Type conversions are lossless only
for closed types/ranges with one canonical representation. Lossy rules require
explicit manifest declaration and produce partial coverage; they cannot be
silently upgraded to complete.

Reverse validation runs after projection for every reversible rule and records
the source-path digest, output-path digest, rule ID, and pass/fail result. A
reverse mismatch denies the transformation rather than publishing a suspect
projection.

## Input inventory and unmapped fields

The executor walks the bounded canonical original object and inventories every
scalar leaf path. Each leaf must be exactly one of:

- mapped by one or more declared rules;
- explicitly ignored by a signed exact-path declaration with a closed reason;
  or
- emitted in the sorted unique unmapped-path list.

Unknown fields are never skipped. `coverage=complete` requires zero unmapped or
lossy source paths. `coverage=partial` requires at least one explicit unmapped
or lossy path. `coverage=unmapped` means no semantic mapping rule applied.
Manifest policy may deny any unmapped field (`deny`) or allow explicit partial
output (`record_partial`); it can never mean `drop` or `guess`.

## Typed entity hints

A rule may declare a closed semantic role such as `host.name`, `user.name`,
`network.ip`, `process.id`, `file.hash`, or `cloud.resource_id`. An emitted hint
binds the case, source envelope/evidence, mapping manifest/rule, canonical
output path, source-field digest, identifier type, normalization method, and a
confidence ceiling. The mapping registry does not emit resolved entity IDs,
merge/split decisions, or cross-case identifiers. CYB-83 must independently
evaluate evidence, counterevidence, confidence, and case-local scope.

## State and failure matrix

| Concern | Required invariant | Closed failure |
|---|---|---|
| Canonical manifest | Unique-key COH-CJ-1, bounded, exact digest and schema/version | `manifest_invalid`, `manifest_digest_mismatch` |
| Signature | Exact domain, publisher/key/revision, Ed25519 signature, trusted purpose | `signature_invalid`, `publisher_untrusted` |
| Time/revocation | Valid now; current exact revocation identity/revision | `manifest_not_yet_valid`, `manifest_expired`, `manifest_revoked`, `revocation_stale` |
| Source match | Every declared source field matches request/envelope | `source_mismatch`, `mapping_not_found`, `mapping_ambiguous` |
| Compatibility | Exact CYB-80 target manifest and OCSF/ECS pins | `target_incompatible`, `mapping_downgrade` |
| Rule language | Closed operations/types/paths/limits; ordered and collision-free | `rule_invalid`, `output_collision`, `type_mismatch`, `conversion_overflow` |
| Coverage | Every scalar input mapped, ignored, or listed unmapped | `unmapped_field_denied`, `coverage_invalid` |
| Reverse proof | Every reversible rule round-trips its canonical scalar | `reverse_validation_failed` |
| Evidence | Exact case and COH-E10/CYB-80 bindings | `evidence_binding_mismatch` |
| Context | Cancellation/deadline checked before and after dependencies and bounded loops | `context_canceled`, `context_deadline` |
| Dependency | No manifest/projection result on verifier/store/audit failure | `dependency_unavailable` |
| Replay | Idempotency key binds canonical command digest | `idempotency_conflict` |

No failure returns a usable projection, manifest selection, or complete-coverage
claim. Audit and error records contain closed codes and digests, not event
values, mapping tables, public keys, or signatures.

## Durable workflow and recovery

1. Validate/canonicalize the command; persist its idempotency key and digest.
2. Verify exact case/evidence/envelope/source bindings.
3. load the exact registry revision and signed manifest without source bytes;
4. verify digest, signature, time, trust, revocation, predecessor, compatibility,
   and exact source match;
5. inventory the canonical original object and execute bounded ordered rules;
6. reverse-validate reversible outputs and compute coverage/unmapped/loss state;
7. construct a candidate CYB-80 envelope and pass it through the CYB-80
   canonical validator; and
8. atomically persist the command, selected manifest digest, mapping outcome,
   normalized-envelope reference, receipt, audit, and provenance.

An exact replay returns the stored receipt. Changed replay is durably denied.
After restart, a stale begun command resumes from exact stored identities. A
lost commit response is recovered by loading the receipt. Cancellation or
timeout stops mapping work and records only a terminal outcome through a short
independent persistence context. No terminal record claims a published
normalized envelope unless its complete atomic commit is resolvable.

## Migration, rollback, privacy, and extension freeze

The initial contract will be `coh.normalization-mapping/v1`, version `1.0.0`.
Any new operation, type, semantic role, source matcher, target pin, or change in
reversibility/coverage semantics requires a new compatibility decision and
corpus replay. Older manifests and readers remain available for historical
events.

Rollback disables new promotion/application and moves only the registry current
pointer to the immediate verified predecessor. It never alters signed manifest
bytes, original fields, OCSF/ECS projections, normalized envelopes, receipts,
audit, or provenance.

Original event fields, source identities, mapping tables, unmapped paths, and
entity hints are sensitive case data. Stores and traces inherit case scope and
classification. Public ports exclude evidence bytes, raw vendor values,
private/public key material, credentials, policy source, paths, URLs, SQL,
network clients, connectors, executors, shell, models, and generic callbacks.

Extensions register a new signed contract version and closed operation/type;
they cannot inject executable behavior into v1 or relax an existing manifest.
