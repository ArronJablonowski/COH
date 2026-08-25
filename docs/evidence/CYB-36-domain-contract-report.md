# CYB-36 domain contract verification report

| Field | Value |
|---|---|
| Issue | COH-E03-01 / CYB-36 |
| Requirements | FR-010, NFR-021 |
| Verification date | 2026-08-25 |
| Source checkpoint | `7c253ac` |
| Contract | `coh.domain/v1` |
| Canonical profile | `COH-CJ-1` |
| Data classification | Internal engineering contract metadata; no credentials or case evidence |
| Review status | Local technical evidence complete; upstream and human approvals pending |

## Outcome

The v1 foundation now has a strict common envelope, 16 registered payload
schemas, executable validation of the exact schema vocabulary in use, canonical
JSON serialization, explicit case-boundary modes, and a positive/negative
fixture corpus. Validation is fail-closed and publishes canonical bytes only
after the envelope, boundary rule, and per-kind payload all pass.

This report does not mark CYB-36 Done. COH-E01/COH-E02 dependency resolution,
independent review, and required Product/Security/Implementation approvals remain
outside the locally verified source checkpoint.

## Delivered artifacts

- Contract bundle: [`contracts/domain/v1`](../../contracts/domain/v1/README.md)
- Compatibility matrix:
  [`domain-contract-compatibility.md`](../design/domain-contract-compatibility.md)
- Production helper: [`internal/helper/domaincontract`](../../internal/helper/domaincontract)
- Executable gate: [`verify_domain_contract.sh`](../../scripts/verify_domain_contract.sh)
- Deterministic ledger: `CYB-36-artifacts.sha256`

## Acceptance evidence

| Acceptance criterion | Evidence | Local result |
|---|---|---|
| Versioned schemas for every required family | Registry plus four strict payload schema documents | Pass: 16 kinds |
| Canonical serialization | COH-CJ-1 writer and deterministic/idempotent/immutability tests | Pass |
| Positive and negative examples | Four positive groups and `payload-denials.json` | Pass: 16 accepted / 16 denied |
| Common envelope denials | Bad time, duplicate key, unknown field, unsupported version plus programmatic bounds | Pass |
| Versioning and compatibility | Dedicated reader/change/migration matrix and exact-version tests | Pass locally |
| Boundary integrity | Registry modes: case self-bound, 13 required, model/skill optional | Pass |
| Invalid and denial behavior | Typed `ErrDenied`; no canonical output | Pass |
| Timeout and cancellation | Distinct `ErrTimeout` / `ErrCancelled`; nil output | Pass |
| Recovery | Same immutable input succeeds after a canceled or expired context | Pass |
| Automated quality gates | Domain gate, unit, race, vet, architecture, size, secrets, licenses, dependencies | See final gate run below |

## Contract-test inventory

The production decoder rejects duplicate keys at token level, trailing values,
malformed input, inputs over 1 MiB, and nesting beyond 64 levels. COH-CJ-1 sorts
object keys, retains array order, emits no insignificant whitespace, rejects
non-integer representations, and does not mutate source input.

The immutable validator loads `contract-registry.json` and its referenced schema
documents. It supports only the bounded JSON Schema vocabulary used by the
tracked v1 bundle: local `$ref`, object properties, required and additional
properties, enums, primitive types, patterns, integer and collection bounds,
item schemas, and `oneOf`. Unknown keywords, unsafe paths, unresolved
definitions, unsupported types, and malformed constraints fail schema loading.

The tracked payload denial corpus has one named example for each kind. It covers
missing and additional properties, invalid enum values, malformed UUID/token/
version/digest values, and integer/array lower bounds. Every positive fixture is
validated twice to prove canonical recovery is byte-stable.

## Failure and lifecycle behavior

| Path | Required observable behavior | Evidence |
|---|---|---|
| Invalid syntax/schema/payload | Deny; return no canonical object | Decoder, envelope, schema-loader, and payload tests |
| Unsupported version/kind | Deny without fallback or field stripping | Envelope fixtures and registered-kind checks |
| Wrong case boundary | Deny before payload publication | Registry-mode tests |
| Deadline already expired | Return `ErrTimeout`; nil output | Envelope timeout test |
| Explicit cancellation | Return `ErrCancelled`; nil output | Envelope and full-validator cancellation tests |
| Recovery | Rerun entire immutable input; produce the same canonical bytes | Envelope and all-kind recovery tests |

Cancellation is cooperative and checked before decoding, after decoding, during
recursive schema validation, and before canonicalization. A timeout or cancel
does not grant authority, fill a boundary, persist partial state, or convert a
denial into success.

## Compatibility and security impact

The exact `coh.domain/v1` identity is the only supported version. Unknown kinds,
versions, and fields deny. Adding a field or kind is not treated as implicitly
safe; it requires mixed-reader qualification. Breaking field, boundary, or
canonical-profile changes require a new version and migration with lineage.

The helper is standard-library-only, performs no network access, reads only the
explicit contract filesystem supplied at construction, and returns safe errors
without echoing input content. It validates representation and structure; it
does not authorize an action, verify referenced evidence, or persist an object.

## Final gate run

The baseline CI orchestrator passed locally on 2026-08-25:

```sh
scripts/run_ci_quality.sh baseline
```

All 18 stages passed: format, file size, workflow policy, worktree and history
secret scans, architecture, quality-contract tests, vet, static analysis, unit,
race, fuzz seeds, licenses, dependencies/offline vulnerability scan, SBOM,
supply chain, evidence-secret scan, and provenance. The local report correctly
sets `quality_gate_promotable=false` because it ran against an evidence worktree
whose documentation had not yet been committed. Clean hosted evidence remains a
publication gate, not a reason to weaken the local checks.

The following focused commands also passed:

```sh
scripts/verify_domain_contract.sh
scripts/check_file_sizes.sh
go test ./...
go test -race ./...
go vet ./...
scripts/check_go_architecture.sh
scripts/check_markdown_links.sh \
  contracts/domain/v1/README.md \
  contracts/domain/v1/fixtures/README.md \
  docs/design/domain-contract-compatibility.md \
  docs/evidence/CYB-36-domain-contract-report.md
```

## Remaining completion gates

- Resolve and record COH-E01/COH-E02 dependency decisions.
- Obtain independent technical review and the required human approvals.
- Attach this report and checksum ledger to CYB-36.
- Keep the issue in Backlog until those gates and the issue's Done criteria are
  satisfied.
