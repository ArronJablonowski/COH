# CYB-95 Splunk authentication and schema discovery report

| Field | Value |
|---|---|
| Issue | COH-E14-01 / CYB-95 |
| Requirements | FR-045, FR-046, SEC-013 |
| Implementation baseline | `ff69d117bd4e494ea278e623b232fcf850b606ba` |
| Focused verification | `scripts/verify_splunk_discovery.sh` passed |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.xqSVLY` |
| CI outcome | 18/18 stages passed; promotable; VCS clean |
| CI report digest | `f91274a287229c4ad4770b56c6cfd778cb63ecc4b91889f9b830d9fe27975ca0` |
| CI report SHA-256 | `f05892934fd61d1c1c6f47b146e9bf84619144e32e8f13ce718dc56c24e7783e` |

## Delivered boundary

- V1 supports only self-managed Splunk Enterprise 9.4 and 10.0 search heads.
  Splunk Cloud remains explicitly unsupported because a separately qualified
  read-only index-inventory surface is not available in this contract.
- The production client exposes exactly four typed GET operations: server info,
  current context, index inventory, and registered-field inventory. There is no
  generic REST method, mutation, login, session-key, token-management, app, or
  search-job surface.
- Every operation validates case/resource authority and exact targets, performs
  a TLS 1.3 chain and SPKI preflight before credential release, consumes one
  broker-owned token lease, rechecks the authenticated connection identity,
  bounds time/bytes/inventory, and emits digest-only receipts.
- Qualification binds the expected GUID, Enterprise product, search-head role,
  qualified minor, required `search` capability, dangerous-capability absence,
  config, transport, lease receipts, and validity window into a verified digest.
- Discovery requires complete bounded inventories. Truncation is unsupported;
  missing configured indexes/fields fail as drift; indexed-required changes are
  explicit conflicts. Only configured logical names and declared types cross
  the common schema SPI.
- Capability and schema identities bind qualification, source, authority,
  resource scope, receipts, and normalized state. Pagination runs only over an
  immutable adapter snapshot using expiring opaque digest-bound cursors.

## Evidence and conformance

The `splunk-10.0` fixture directory contains six sanitized deterministic
recordings: identity, current context, indexes, registered fields, redacted
denial, and duplicate-key adversarial input. Its manifest declares no sensitive
values. Local TLS replay verifies exact methods, paths, queries, lease timing,
headers, TLS substitution resistance, bounds, response decoding, and redaction.

Public evidence includes strict closed configuration, qualification, denial,
and redacted-error schemas; valid secret-free config; digest-verified
qualification; common capability and schema snapshots; denial corpus; and
redacted trace. The verifier and `CYB-95-artifacts.sha256` bind these artifacts.

Adversarial coverage includes endpoint/base-path/redirect drift; caller target
and authority substitution; pre-lease TLS substitution; credential injection;
invalid receipts; GUID/product/role/version/capability drift; missing and
dangerous capabilities; oversized, malformed, duplicate, partial, and truncated
responses; missing indexes/fields; indexed-field conflicts; unconfigured-field
non-disclosure; cursor substitution; cancellation; deadlines; outage/recovery;
qualification/capability staleness; schema-cache coalescing; and concurrent
cursor replay under the race detector.

The clean full baseline passed format, file-size, workflow, worktree/history
secret scans, architecture, quality contract, vet, static analysis, unit, race,
fuzz seeds, license, dependency/vulnerability, SBOM, supply-chain, evidence
secret scan, and provenance stages.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Scoped auth, allowed indexes/fields, capability validation, token/SID redaction | Typed transport, qualifier, adapter, fixtures | Pass |
| Typed operations, resource bounds, cancellation, explicit partial/unsupported behavior | Contracts and adversarial suites | Pass |
| Invalid input, denial, timeout/cancel, recovery preserve policy/provenance | Transport and adapter recovery suites | Pass |
| Applicable CI, race, architecture, secret, license, dependency, size gates | Focused verifier and clean 18/18 baseline | Pass |
| Vendor fixture, capability, conformance report, redacted trace attached | Versioned evidence and checksums | Pass |

## Residual release condition

No CYB-95 blocking finding remains. The approved product-level follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
