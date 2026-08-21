# COH domain contract v1

| Field | Value |
|---|---|
| Issue | COH-E03-01 / CYB-36 |
| Status | Draft — blocked by COH-E01 approval |
| Requirements | FR-010, NFR-021 |
| Contract version | `coh.domain/v1` |
| Canonical encoding | `COH-CJ-1` |
| Data classification | Operational metadata and workflow identifiers |

This directory will define the versioned wire and persistence-neutral contracts
shared by the API, workflows, stores, evidence service, broker, providers,
connectors, and export tooling. It does not define database tables, vendor payloads,
transport framing, authorization policy, or executable authority.

The PRD remains normative. This draft freezes the v1 inventory, namespace,
canonical encoding profile, and compatibility rules before executable schemas and
fixtures are added. It does not claim CYB-36 is complete or approved.

## Contract inventory

Every required family has one registered lower-case kind. A family may gain
versioned subtypes later, but aliases cannot silently replace these canonical
identities.

| Kind | Purpose | Required identity and provenance |
|---|---|---|
| `case` | Investigation and custody boundary | Organization, tenant, case, owner, classification, lifecycle version |
| `run` | Durable workflow invocation | Case, initiating actor, workflow type/version, policy revision, provider route |
| `task` | Leased bounded unit of work | Run, parent task, attempt, lease, deadline, immutable input/output references |
| `evidence` | Immutable collected or derived artifact | Digest, media type, length, classification, access scope, source manifest |
| `finding` | Reviewable analytical conclusion | Case, status, severity, confidence, claims, evidence, counterevidence, owner |
| `claim` | Exact evidence-grounded statement | Case, statement, author, confidence, evidence and counterevidence references |
| `timeline_event` | Time-normalized observation | Case, source and normalized time, precision, uncertainty, entities, evidence |
| `query` | Bounded external-data request and result state | Case, connector, target, half-open time range, purpose, limits, plan and result references |
| `action` | Canonical proposed or executed side effect | Case, actor, tool/version, exact targets/arguments, tier, policy and ROE references |
| `approval` | Human decision bound to an exact action | Action digest, approver, decision, validity, use count, policy/ROE digests |
| `roe` | Signed rules of engagement | Case, inclusions/exclusions, window, methods, rates, stop/rollback, approvers |
| `model` | Requested and actual inference identity | Provider, requested/actual model, immutable revision/digest, runtime and parser versions |
| `skill` | Reviewed analysis or workflow capability | Stable identity/version, content digest, provenance, capabilities, promotion state |
| `vulnerability` | Evidence-linked vulnerability lifecycle record | Asset, observation, identifiers, assertions, priority rationale, remediation and retest state |
| `risk` | Explainable risk assertion | Subject, method/version, ordered factors, evidence, uncertainty, owner and disposition |
| `artifact_manifest` | Transformation and custody lineage | Artifact, sources, collection/source times, transformation and tool/query/model versions |

The registry file `contract-registry.json` is the machine-readable inventory. A
kind absent from that registry is unknown and must be rejected rather than inferred.

## Common envelope

Every encoded domain object uses this logical envelope:

```json
{
  "schema": "coh.domain/v1",
  "kind": "case",
  "id": "0198d6c4-7618-7d31-8e0a-9da53cae8ca2",
  "organization_id": "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e",
  "tenant_id": "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16",
  "case_id": "0198d6c4-7618-7d31-8e0a-9da53cae8ca2",
  "revision": 1,
  "created_at": "2026-08-21T20:00:00.000000000Z",
  "data": {}
}
```

`organization_id`, `tenant_id`, and `case_id` are explicit authorization and
storage boundaries. A contract that legitimately precedes case creation uses the
separately defined nullability rule in its schema; implementations may not invent,
copy from model output, or default a missing boundary.

The envelope never contains raw credentials, reusable capabilities, arbitrary
vendor payloads, unbounded evidence bytes, full prompts, or executable code.
Those values remain behind dedicated trust boundaries and are referenced only by
typed immutable identifiers when allowed.

## COH-CJ-1 canonical JSON

Canonical bytes are used for digests, optimistic concurrency, approvals,
signatures, replay detection, evidence manifests, and compatibility fixtures.
Implementations must produce one representation for one logical value:

1. Input is valid UTF-8 JSON and contains exactly one top-level object.
2. Duplicate object keys, unknown fields, invalid UTF-8, comments, trailing data,
   and non-JSON numeric tokens are rejected before canonicalization.
3. Object members are encoded in ascending Unicode code-point order of their
   unescaped field names. Arrays retain semantic order unless the owning schema
   explicitly declares a set.
4. Schema-declared sets are de-duplicated and sorted by their canonical element
   bytes. A caller cannot use input order to change a digest.
5. Numbers are base-10 integers within the schema-declared range. Floating-point,
   exponent, negative-zero, NaN, and infinity representations are forbidden in v1.
6. Strings use the shortest JSON escapes required for control characters, quote,
   and reverse solidus. `/`, `<`, `>`, `&`, and printable non-ASCII characters are
   not escaped. Unicode normalization is not performed; schemas constrain fields
   that require a normalized form.
7. Timestamps are RFC 3339 UTC with exactly nine fractional digits and `Z`.
   Original timezone, source precision, and clock uncertainty are separate fields.
8. UUID identifiers use lowercase RFC 9562 text. Digests use lowercase
   `algorithm:hex`, initially `sha256:` followed by 64 hexadecimal characters.
9. Optional absent values are omitted. JSON `null` is accepted only where the
   schema explicitly makes it a state with distinct meaning.
10. Canonical output has no insignificant whitespace, byte-order mark, or trailing
    newline.

Canonicalization validates syntax and representation; it does not authorize the
object, verify referenced evidence, grant approval, or make hostile content trusted.

## Validation and failure behavior

Validation is ordered and fail-closed:

1. Enforce input byte, nesting, string, array, and object-member bounds before a
   complete in-memory representation is required.
2. Decode with duplicate-key and trailing-data detection.
3. Resolve the exact `schema` and registered `kind`; unknown versions and kinds
   are denied.
4. Validate the common envelope, tenant/case boundary requirements, and the exact
   per-kind schema with unknown fields disabled.
5. Validate cross-field invariants that JSON Schema cannot express.
6. Canonicalize, hash, and compare with any supplied digest.
7. Publish or persist only after every step succeeds.

Malformed, oversized, cancelled, or timed-out validation publishes no resolvable
object. Cancellation is checked between bounded phases. Recovery can rerun the
same immutable input; it cannot reinterpret a denied version, fill missing
authority fields, or upgrade data silently. A digest mismatch quarantines the
temporary input and returns a safe error without exposing its content.

## Versioning and compatibility

| Change | v1 compatibility result | Required action |
|---|---|---|
| Clarify documentation without changing accepted bytes or meaning | Compatible patch | Update tests and explanatory version metadata |
| Add an optional field with a deterministic absent default | Additive within v1 only after old readers demonstrably preserve or reject it safely | Add forward/backward fixtures and capability negotiation |
| Add a required field or tighten an accepted value | Breaking | Introduce a new schema version and migration |
| Remove, rename, or change the meaning/type of a field | Breaking | Introduce a new schema version and explicit translation |
| Change canonical ordering, normalization, timestamp, identifier, or digest rules | Breaking | New canonical profile and schema major version |
| Add a registered kind | Additive registry revision | Qualify old readers' unknown-kind denial and new-reader fixtures |
| Reuse a removed kind or field name with new meaning | Forbidden | Allocate a new identity |
| Accept unknown fields for pass-through | Forbidden | Model the extension explicitly or deny it |

Readers must advertise exact schema and kind support. Writers select only a
mutually supported version. Storage retains original canonical bytes and version;
migration writes a new object with lineage to the source rather than rewriting
custody history. API `/api/v1` compatibility does not imply every domain schema is
understood; capability discovery exposes that distinction.

## Planned executable artifacts

The following short tasks remain before CYB-36 can be reviewed for completion:

- [x] Publish the strict common-envelope JSON Schema and initial envelope fixtures.
- [ ] Publish the 16 strict per-kind JSON Schemas (12/16 drafted: `case`, `run`,
  `task`, `artifact_manifest`, `evidence`, `finding`, `claim`, and
  `timeline_event`, `query`, `action`, `approval`, and `roe`).
- [ ] Add one canonical positive fixture for every kind.
- [ ] Add malformed, duplicate-key, unknown-field, wrong-boundary, bad-time,
  bad-digest, oversized, cancellation, and unsupported-version denial fixtures.
- [ ] Implement bounded Go validation and COH-CJ-1 canonical serialization.
- [ ] Prove canonical determinism, idempotence, and source-input immutability.
- [ ] Publish the compatibility matrix and contract-test report.
- [ ] Run architecture, race, size, secret, license, and dependency gates.
- [ ] Obtain dependency and human approval, then attach exact digests to CYB-36.

## Change control

Changes require a linked issue, owner, requirement trace, migration and workflow
replay assessment, positive and denial fixtures, compatibility classification,
and reviewer sign-off. Emergency policy may reject more objects immediately but
cannot widen a schema, reinterpret existing canonical bytes, or grant authority.
