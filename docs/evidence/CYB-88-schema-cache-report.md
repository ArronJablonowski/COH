# CYB-88 bounded schema-cache verification

| Field | Value |
|---|---|
| Stable key | COH-E12-03 |
| Requirements | FR-045, FR-054 |
| Implementation commits | `48bcf03`, `0158c37`, `b04de5c`, `27062a9` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `d5d4cee5094445c35bedcf5860b48d1bdd40327b0baf5c36854ab4e0eb0d4f9f` |
| CI report file SHA-256 | `410086256a5eb554eec94a9650ee76d8c8f997ea99c5a773064d00762a4533db` |
| Canonical identity fixture digest | `sha256:dd5207492cd0a8a5ad7a7f584b10e88c61125401b742c18086b6318017b6de2c` |

## Evidence locations

- Public identity schema: `contracts/schema-cache/v1/schema-cache-entry.schema.json`
- Canonical identity fixture: `contracts/schema-cache/v1/fixtures/entry-identity.canonical.json`
- Contract documentation: `contracts/schema-cache/v1/README.md`
- Threat model: `docs/design/bounded-schema-cache.md`
- Focused evidence: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB88.QlEHyg`
- Adversarial trace: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB88.QlEHyg/adversarial.log`
- Focused race report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB88.QlEHyg/race.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.9ecwkY/quality-report.json`

The hashes in [`CYB-88-artifacts.sha256`](CYB-88-artifacts.sha256) identify the
contract, focused, and baseline evidence.

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Schema discovery is tenant/source scoped, versioned, TTL bounded, invalidatable, size limited, and safe under stale or unavailable metadata. | `Cache.Get` keys organization, tenant, source, exact resource-scope digest, capability digest, adapter version, and connector schema version. Tests prove isolation, TTL/capability expiry, stale fail-closed refresh, scoped idempotent invalidation, hard configuration/entry/total-byte caps, and deterministic LRU eviction. |
| The Go boundary is narrow, typed, cancelable, idempotent, and does not bypass policy or execution. | The single-method `Loader` accepts only an authority-bearing CYB-85 `SchemaRequest`; the cache exposes no transport, credential, policy, or execution method. Typed errors cover invalid, denied, canceled, timeout, unavailable, conflict, and internal outcomes. Exact concurrent misses coalesce, while independently canceled waiters do not poison the bounded load. |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance. | Tests deny invalid config, substituted capability, malformed scope, nil context, partial pages, cross-resource widening, oversized pages, stale capability, and in-flight invalidation. Loader timeout and outage recovery are typed. Immutable schema-page, vendor-schema, and provenance digests remain bound in the canonical entry identity. |
| Automated tests and repository gates pass. | Focused verbose/adversarial, 10-repeat, race, vet, static, architecture, file-size, and contract-verifier checks passed. Clean commit `27062a9` passed all 18 baseline stages, including secrets, licenses, vulnerabilities, SBOM, supply-chain, and provenance. |
| Required evidence cross-references the issue and requirements. | This report, retained logs, public schema/fixture, checksums, design record, and verifier identify COH-E12-03, CYB-88, FR-045, and FR-054. |

## Freshness, concurrency, and recovery

Effective expiry is the earlier of configured TTL and the validated capability
`valid_until`. Expired data is removed before capacity eviction and is never
served as a fallback when a vendor loader is unavailable. Only complete schema
pages without continuation handles are cacheable, and every returned field must
remain inside the exact requested resource allowlist.

One bounded load runs per exact key. Waiters may cancel independently. Scoped
invalidation marks matching in-flight loads so they return a typed conflict and
cannot insert after invalidation. A later call retries from immutable request
and capability inputs. Fresh hits preserve the originating schema page and its
provenance; they do not create or imply a new policy decision.

## Privacy and authority boundary

The memory-only cache stores validated schema metadata and redacted digests. It
does not store credentials, query text, rows, URLs, raw vendor errors, policy
decisions, approvals, or audit records. Current policy/query admission remains
mandatory outside the cache on every operation; a cache hit grants no authority.

## Migration, rollback, and release follow-up

Key fields, TTL meaning, completeness requirements, stale-data behavior,
invalidation selectors, canonicalization, and provenance bindings are
security-sensitive. Changes require a new major contract and adversarial
migration evidence. Rollback clears process-local cache state and never rewrites
query, schema, or provenance records.

No unresolved blocking finding remains. An independent security architecture
review remains required before the first production release.

## Verification summary

The focused and baseline evidence proves all CYB-88 acceptance criteria at
clean commit `27062a9cd9d7f0c9f3a5d06f90e0bcf6142f5a87`.
