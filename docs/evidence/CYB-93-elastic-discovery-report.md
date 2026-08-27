# CYB-93 Elastic authentication and schema discovery report

| Field | Value |
|---|---|
| Issue | COH-E13-01 / CYB-93 |
| Requirements | FR-045, FR-046, SEC-013 |
| Implementation baseline | `1b6a265b65fca65d43dc039c33769fe9ff50d119` |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.6UMd1n` |
| CI outcome | 18/18 stages passed; VCS clean |
| CI report digest | `303f8ef0a28970dbc0ce10131474d8e4273d2dc0213bb6012fa817b40cd7e5b0` |
| CI report SHA-256 | `fbbdb747f8d60211108bfbd92c5315281ff0cb10dec1d400b464e31d8e42f536` |

## Delivered boundary

- The adapter publishes a strict read-only capability only after exact HTTPS
  source, cluster UUID, build flavor, qualified version family, TLS 1.3 peer,
  case/resource scope, and authority validation.
- The production transport has only three methods: cluster inspection, target
  resolution, and field capabilities. It disables ambient proxies, redirects,
  compression, and keep-alive reuse; pins the peer SPKI; bounds deadlines and
  response bytes; and produces only request, response, lease, and transport
  digests.
- Authentication consumes one temporary API-key value through the credential
  source callback per call. The value is never returned, persisted, placed in a
  cursor or evidence record, or included in a vendor error. The credential
  broker remains responsible for issuance, fresh authority, single-use
  dispatch, audit-before-use, secret resolution, destruction, rotation, and
  revocation.
- Caller scope maps logical COH resource IDs to configured local Elastic
  expressions. Remote syntax, broad wildcards, hidden/restricted/system/closed
  targets, request-selected fields, target drift, alias substitution, and data
  streams are denied or explicitly unsupported.
- Field capabilities use exact resolved indices, explicit sorted fields,
  `allow_no_indices=false`, `ignore_unavailable=false`,
  `expand_wildcards=open`, and `include_unmapped=true`. Missing configured
  fields, unsearchable/unknown/conflicting types, or changed membership cannot
  become a complete schema.
- Capability and schema cache identities bind the source, authority, qualified
  cluster, configuration, resource scope, and capability digest. Adapter-owned
  cursors contain only digests and UUIDs, expire with the capability, and
  produce deterministic idempotent pages under replay and concurrency.

## Vendor and public evidence

The versioned `elastic-8.19` testdata directory is a sanitized deterministic
replay recording derived from the Elastic 8.19 response contracts. Its manifest
identifies the origin and asserts that it contains no sensitive values. It
includes cluster information, index resolution, field capabilities, and a
privilege-denial body. The TLS harness replays those bodies through a real local
TLS server and verifies method, escaped path, exact query parameters,
authorization lifecycle, SPKI pinning, and response decoding.

`contracts/elastic-discovery/v1/fixtures/capability.snapshot.json` is accepted
by the shared strict `coh.query-capability/v1` decoder. The public configuration
schema excludes credentials and generic transport fields. The redacted error
trace contains only bounded identities and digests and asserts that neither a
credential nor vendor body was exposed.

## Verification

`scripts/verify_elastic_discovery.sh` passed repeated focused tests, race
detection, vet, static analysis, architecture policy, file-size policy, public
schema assertions, capability decoding, vendor-fixture checks, and redacted
error assertions.

Adversarial coverage includes plaintext and proxy-style endpoints, base paths,
remote clusters, `_all`/bare/hidden targets, wildcard fields, unqualified
versions, cluster/build/TLS substitution, malformed receipts, target and alias
substitution, data streams, field widening, missing fields, conflicting and
unsupported field types, stale and widened capabilities, cursor substitution,
pagination replay, oversized responses, privilege denial, vendor outage,
deadline, caller cancellation, recovery, cache hits, and concurrent cursor
replay.

The clean full baseline passed format, file-size, workflow, worktree/history
secret scans, architecture, quality contract, vet, static analysis, unit, race,
fuzz seeds, license, dependency/vulnerability, SBOM, supply-chain, evidence
secret scan, and provenance stages.

## Explicit unsupported behavior and rollout

This leaf does not query events; CYB-91 and CYB-94 add bounded ES|QL and Query
DSL execution. Elastic data streams are explicitly unsupported in v1 because
their hidden backing indices require a separate admission model. Unknown major
versions, unqualified minor families, snapshot builds, and unqualified
Serverless deployments fail closed.

Operators must provision a dedicated API key with cluster `monitor` and index
`view_index_metadata` plus `read` only for configured targets. Because Elastic
unions permissions across roles, the principal must have no write or broader
index role. Rollout, rotation, migration, recovery, and rollback procedures are
published in the contract README and design record.

## Residual release condition

No CYB-93 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
