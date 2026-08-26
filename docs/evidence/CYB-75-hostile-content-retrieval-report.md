# CYB-75 hostile-content retrieval verification

| Field | Value |
|---|---|
| Stable key | COH-E09-04 |
| Requirements | FR-044, SEC-001, SEC-016, EVAL-022 |
| Implementation commit | `a1514c956beb598b2ac41e842c7ad443cac2fe7a` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI report digest | `e31f904cc78562bbe4a1dccdc58c88d7f56e2565a288c0d1041e65c6cf2a2830` |
| CI report file SHA-256 | `5e6c96d9e1fbec309e328383ec94c9194cc66d816bfa7c97b387b94974407054` |
| Focused verifier log SHA-256 | `bf2f34f2d436b8e24a7ecd547744a58e1a0ff80cd2de3a57866b1134b1b59304` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB75.gpmHMf/hostile-content-retrieval.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.1HctLK/ci-provenance.json`

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Closed v1 records | The public schema and Go contract freeze strict request, decision, inspection, and durable record shapes. Contract tests compare schema versions, contract versions, wire fields, trust constants, source kinds, and finding codes to code. Every nested object rejects additional properties. |
| All retrieved content is untrusted | Logs, documents, feeds, query output, tool output, tool errors, memory, reports, and attachments are the only source kinds. Both source and sanitized result retain the fixed `untrusted_content` label; no finding-free path upgrades trust. |
| Exact default-deny authorization | Authorization binds request, actor and revision, organization/tenant/case/task, immutable source and provenance, strict profile, policy digest, revocation digest, and deadline. Canonical decision digests and every returned field are recomputed and compared before inspection. Denial, malformed decisions, expiry, cancellation, timeout, and unavailable authority fail closed. |
| Data-only inspection boundary | `Inspector` receives one immutable source, strict profile, intent digest, and deadline. Reflection and architecture tests prohibit prompt, instruction-text, raw bytes, credential values, approval, scope override, policy source, paths, URLs, callbacks, connectors, executors, commands, and executable interface fields. |
| Deterministic rendering and sanitization | The inspector verifies exact source digest, length, UTF-8, media/byte profile, and provenance, then writes canonical JSON with explicit `trust`, source digest/media type, and `data`. Secret values are redacted and active markup characters are neutralized before writing. The exact output digest, type, classification, and length are verified. |
| Malformed and partial input | Empty, malformed UTF-8, truncated/length-drifted, digest-drifted, oversized, writer-drifted, incomplete, canceled, and dependency-failed results never produce a releasable completed inspection. Sanitized output is independently capped by the strict profile. |
| Adversarial evaluation | Every one of the nine source kinds runs the instruction/scope-change/authorization-forgery/credential/tool/exfiltration/active-content/encoded-payload/secret corpus. All nine finding classes are recorded, the dummy secret value and active tag are absent from output, and the result remains JSON data marked `untrusted_content`. |
| Zero authorization or scope mutation | The adversarial bytes are available only to the data-only inspector. Controller tests prove the authority receives and returns the original exact case, task, actor, actor revision, policy, and source kind; inspector results have no field capable of changing those values or granting tool authority. |
| Fail-closed audit | A sanitized result is committed and its historical allow event appended before release. Audit unavailability returns no result. Policy denial, changed replay, invalid inspection, missing sanitized artifact, and invalid audit proof append denial evidence without hostile bytes or secret values. Distinct reasons have distinct deterministic event identities. |
| Idempotency, replay, and provenance | The case/task/idempotency key resolves one canonical durable record. Exact replay rechecks current authority/revocation, re-verifies the sanitized artifact, repairs the historical audit proof, and appends a fresh replay-authorization event. Changed replay is denied. Provenance chains from source through the complete inspection and audit record. |
| Crash and restart recovery | SQLite integration commits an inspection, simulates audit failure, closes and reopens the database, reauthorizes and verifies the durable sanitized artifact without reading hostile bytes again, repairs audit evidence, and denies changed replay. |
| Model-facing skill resources | Progressive skill search/detail remain metadata-only. Resource fetch must invoke `HostileContentGuard` as `document` and returns only source evidence digests plus the sanitized inspection result; its public result has no raw `Artifact` field. |
| Model-facing memory | Memory first passes CYB-72 namespace/access/retention/review checks, then invokes `HostileContentGuard` as `memory`. Its public result has no raw memory `Record` and returns only metadata, evidence digests, and the sanitized inspection result. |
| Storage and rollback | The generic case-scoped metadata envelope recognizes `retrieval`; existing SQLite/PostgreSQL tables need no DDL change. Documented cutover enables the guard before model-facing adapters. Prior binaries reject the unknown kind, so rollback disables retrieval and fails closed while retaining records for forward recovery. |

## Requirement trace

- **FR-044:** every retrieved log, document, feed, query/tool result, tool
  error, memory value, report, and attachment is typed as untrusted data and
  reaches model-facing skill and memory paths only as a verified sanitized
  artifact.
- **SEC-001:** hostile content never enters the authority request or decision
  surface and cannot grant identity, scope, authorization, approval,
  credentials, or tool capability.
- **SEC-016:** canonical JSON rendering, explicit trust labels, secret
  redaction, active-content neutralization, narrow ports, and model-facing
  result types keep embedded instructions on a data-only path.
- **EVAL-022:** the adversarial corpus runs for all nine source kinds and proves
  injection, scope change, forged authorization, credential requests, tool
  directives, exfiltration, active content, encoding tricks, and secret-like
  text cause zero authorization or scope changes.

## Verification summary

The focused verifier passed schema closure, frozen wire synchronization,
boundary reflection, all-source adversarial sanitization, authorization and
revocation, policy denial, partial/malformed/oversized input, exact and changed
replay, lost responses, audit recovery, cancellation, timeout, agent-loop
integration, SQLite close/reopen, repeated execution, race detection, vet,
static analysis, architecture, file-size, link, and clean-diff checks.

The clean baseline then passed all 18 required stages: format, file-size,
workflow, worktree/history/evidence secret scans, architecture, quality
contract, vet, static analysis, unit, race, fuzz seeds, license,
dependency/vulnerability, SBOM, supply chain, and provenance. No unresolved
blocking finding remains for CYB-75.
