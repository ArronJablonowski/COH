# CYB-20 Elastic and Security Onion connector integration report

| Field | Value |
|---|---|
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-045, FR-046, SEC-013, FR-048, FR-049, FR-050, FR-054, EVAL-016 |
| Children | CYB-93, CYB-91, CYB-94, CYB-90, CYB-89 — all Done |
| Integration checkpoint | `de0d5879812c9fec1ae8a6b8247c525dec17d1d5` |
| Full CI | 18/18 stages passed, `vcs_modified:false` |
| Residual production condition | Independent security architecture review before first production release |

## Integrated connector boundary

Elastic and Security Onion implement the common read-only query connector
without generic HTTP, shell, query-language, credential, or mutation surfaces.
Every operation is typed, authority- and capability-bound, resource allowlisted,
deadline-limited, strictly decoded, and represented by redacted digest-bearing
receipts. Credentials are lent only after the configured TLS and policy boundary
is verified and never enter results, errors, traces, or evidence.

Elastic discovery, bounded ES|QL, and Query DSL/PIT export expose only reviewed
endpoints. Complete Query DSL export uses an owned point-in-time handle and
stable `search_after`; cursor, PIT, index, authority, and schema substitutions
fail closed. Security Onion exposes only the documented Connect and OQL
read-only operations against allowlisted datasets. Vendor caps or inability to
prove completion produce explicit partial/unknown results or bounded slicing;
they never become a complete claim.

## Integration verification

The following exact-checkpoint verifier chain passed:

- `scripts/verify_elastic_discovery.sh`
- `scripts/verify_elastic_esql.sh`
- `scripts/verify_elastic_querydsl.sh`
- `scripts/verify_security_onion.sh`
- `scripts/verify_connector_truncation.sh`
- `scripts/verify_e12_integration.sh`

The chain covers common query conformance, allowlisted resource and endpoint
binding, malicious ES|QL/Query DSL/OQL input, stable paging, cancellation,
timeout, retry/recovery, PIT expiry and cleanup, explicit truncation, adaptive
slicing, partial-result denial, tamper, redaction, and concurrent replay. The
locked truncation evaluator passed 21 tasks and 105 repeated trials with zero
false-complete, duplicate, or missing rows and 1.0 outcome, trajectory, replay,
and boundary-coverage rates.

Child evidence packets:

- `docs/evidence/CYB-93-elastic-discovery-report.md`
- `docs/evidence/CYB-91-elastic-esql-report.md`
- `docs/evidence/CYB-94-elastic-querydsl-report.md`
- `docs/evidence/CYB-90-security-onion-report.md`
- `docs/evidence/CYB-89-connector-truncation-report.md`

The clean checkpoint also passed the authoritative 18-stage offline baseline,
including repository unit/race, architecture, static analysis, secret scans,
license inventory, dependency/vulnerability checks, SBOM, supply-chain
reproducibility, and provenance. The exact final report-commit CI run is retained
in the CYB-20 closure comment.

## Operations, migration, recovery, and rollback

- Start each source disabled. Configure a dedicated least-privilege identity,
  exact endpoint/TLS pins, allowlisted indices or datasets, current policy, and
  fresh qualification before enabling query traffic.
- Any endpoint, identity, schema, API, parser, paging/slicing, stable-key,
  completion, or vendor-version change requires a reviewed contract/fixture
  revision and fresh qualification. Historical evidence is immutable.
- Timeout, cancellation, partial response, cap exhaustion, uncertain retry,
  lost PIT/cursor state, or vendor outage releases no unproven complete result.
  Recovery obtains current authority and a fresh credential lease, then starts a
  new attempt or resumes only an exactly bound recoverable cursor.
- Rollback disables the source, revokes leases and policy decisions, closes
  connector-owned PIT/jobs where confirmable, expires local handles, restores
  the prior reviewed binary/configuration, and retains only redacted evidence.

## Integration acceptance

| Criterion | Evidence | Outcome |
|---|---|---|
| Elastic and Security Onion pass common query, malicious-query, paging/slicing, cancellation, and partial-result suites | Six-verifier integration chain and child packets | Pass |
| Elastic complete export uses PIT/search_after; Security Onion exhaustion is explicit truncation or bounded slicing | Query DSL and truncation evaluator evidence | Pass |
| Only documented read-only endpoints and allowlisted indices/datasets are reachable | Typed transports, architecture and hostile-boundary tests | Pass |

All five children and all three parent integration criteria are complete. No
CYB-20 blocking finding remains.
