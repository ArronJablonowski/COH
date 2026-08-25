# COH platform and support matrix

| Field | Decision |
|---|---|
| Document ID | COH-E01-04 |
| Status | Approved for M0 design freeze |
| Owner | COH product owner / project lead (Arron Jablonowski) |
| Required approvers | Product owner, security architecture, and implementation |
| Approval status | Approved 2026-08-25 at source checkpoint `8c6012d`; qualification evidence remains required for release claims |
| Effective baseline | Research snapshot 2026-08-19 |
| Change control | Reviewed PRD revision plus updated qualification evidence |

This document defines which deployment profiles COH v1 intends to qualify. It
does not claim that an unreleased profile is implemented, supported, or suitable
for production. The [PRD](../../outputs/COH-PRD.md) remains normative.

## Support vocabulary

| Term | Meaning |
|---|---|
| Tier 1 | Release-blocking profile after version-specific qualification evidence passes |
| Optional | Supported packaging or service that is never a prerequisite for native operation |
| Best effort | Not release-blocking; limitations are explicit and failures do not weaken Tier 1 claims |
| Qualified | The exact OS, architecture, runtime, package, and COH revision passed its required suite |
| Experimental | Available only with an explicit warning; not represented as supported |
| Unsupported | Not advertised, dispatched, or silently substituted |

Labels describe evidence status, not aspiration. Missing, stale, mismatched, or
incomplete qualification evidence leaves a profile experimental or unsupported.

## Normative platform matrix

| Profile | Architecture and runtime | Intended support | Required qualification | Explicit limitations |
|---|---|---|---|---|
| Native macOS workstation | macOS 14+ arm64; native COH services; SQLite and local evidence store | Tier 1 | Clean install with Docker absent; local-model invocation; case, bounded query, timeline, signed export; backup, upgrade, rollback, removal | Loopback workstation profile; native Ollama or llama.cpp is preferred for Metal; T4 never runs on the workstation |
| Native Linux server | Linux amd64; native services; PostgreSQL 18 and configured evidence store | Tier 1 | Clean install; server persistence; service identity/mTLS; reference workflow; backup, upgrade, rollback, removal | Distribution and kernel combinations require exact published qualification; no generic shell or Docker dependency |
| Native DGX | Linux arm64 on NVIDIA DGX Spark; native control plane; selected inference service may use GPU | Tier 1 | Native Linux suite plus GPU isolation, resource reservation, and inference qualification | GPU is exposed only to the selected inference service, never validators, broker tools, or untrusted runners |
| Compose on macOS | Docker Desktop Linux VM; complete Compose application profile | Tier 1 optional packaging | Documented Compose start; API, policy, workflow, schema, and artifact parity; backup/upgrade/removal | Docker remains optional; hosted/CPU inference supported; shared Docker Desktop is not a T4 boundary |
| Compose on Linux | Docker Engine with Compose; complete application profile | Tier 1 optional packaging | Same parity and lifecycle suites as native Linux | No Docker socket mounts, floating tags, public database/workflow ports, or secrets in environment variables |
| Windows host | Windows with a qualified Docker Desktop/Compose profile | Best effort, Docker-only | Smoke and parity results may be published for exact qualified combinations | No Windows-native v1 services; not a release gate; never infer support from Linux-container compatibility alone |

Docker absence must not alter native APIs, policy semantics, workflows, evidence
formats, or security boundaries. Native and Compose profiles use the same public
contracts and conformance fixtures. Ordinary native or Compose execution is not
eligible for T4; T4 requires a separately enrolled disposable VM or approved
isolated remote zone.

## Connectivity profiles

| Profile | Permitted behavior | Qualification and failure behavior |
|---|---|---|
| Connected | Explicitly configured provider, connector, identity, update, and time endpoints may be used through typed policy-bound adapters | Egress outside the configured allowlist is denied and audited |
| Restricted connected | Only an operator allowlist of endpoints and offline-pinned content is permitted | Missing endpoints degrade the named capability; COH does not widen egress or select an unapproved fallback |
| Air-gapped | Signed offline bundles, local providers, local data sources, and operator-supplied trusted time are used | A 24-hour test must observe zero DNS, Internet, telemetry, update, activation, or external time-service attempts |

Air-gap mode is a first-class operating profile, not merely connected mode with
failed requests. Online capability absence must be reported explicitly without
retry storms, hidden activation, or silent routing to a hosted provider.

## Support-claim and failure rules

| Condition | Required result |
|---|---|
| Unknown OS, architecture, runtime, or profile | Reject the support claim; report the missing qualification path |
| Docker is absent in a native profile | Continue native operation without probing for or requiring a daemon, socket, executable, or VM |
| Docker is absent for a Compose request | Return a bounded prerequisite error; do not alter native state |
| Qualification evidence is missing, stale, or for a different version | Mark the exact combination experimental or unsupported; do not advertise it as Tier 1 |
| A component becomes unavailable before work | Preserve state and return degraded/unavailable without widening routes or authority |
| Interruption occurs during install, upgrade, backup, restore, or removal | Resume safely or roll back according to the profile procedure; never claim success from partial state |
| Native and Compose conformance differs | Block the affected release/profile claim until the incompatibility is resolved or explicitly versioned |
| A Windows-only failure occurs | Record the best-effort limitation without weakening or misrepresenting Tier 1 results |

Cancellation preserves the last verified state and removes uncommitted temporary
artifacts. Recovery reruns only idempotent checks or documented lifecycle steps.
No platform label grants model, connector, runner, or T4 authority.

## Alternatives and non-goals

| Alternative | Decision |
|---|---|
| Require Docker for all installations | Rejected; it violates native-first operation and local inference goals |
| Treat all Linux distributions as qualified | Rejected; support belongs to exact tested combinations |
| Treat Docker parity as automatic | Rejected; parity requires shared contract evidence |
| Claim Windows-native support | Rejected for v1; Windows is best-effort Docker-only |
| Use shared Compose as T4 isolation | Rejected; T4 requires an independent enrolled execution zone |
| Hide unfinished support behind a feature flag | Rejected; evidence, not flags or dates, governs support claims |

This decision does not implement packaging, installers, Compose files, GPU
configuration, air-gap enforcement, lifecycle procedures, or T4 runners. It does
not activate policy or promise support before qualification.

## Requirement traceability

| Requirement | Decision evidence | Required release evidence |
|---|---|---|
| NFR-001 | Normative platform matrix identifies macOS arm64, Linux amd64, Linux arm64/DGX, and Docker Desktop/Engine Tier 1 profiles | Exact versioned clean-install and reference-workflow results |
| NFR-002 | Docker is optional and Docker-absent native behavior is explicit | Native test with executable, daemon, socket, and VM absent |
| NFR-003 | Native and Compose share public contracts and parity gates | API, policy, workflow, schema, and artifact conformance report |
| NFR-030 | Support vocabulary and failure rules deny unqualified claims | Published evidence index proving every advertised combination |

## Approval checklist

- [x] COH-E01-01, COH-E01-02, and COH-E01-03 are approved.
- [x] Product owner approves profiles, vocabulary, and explicit limitations.
- [x] Security architecture approves Docker, DGX, air-gap, and T4 boundaries.
- [x] Implementation reviewer confirms every qualification gate is executable.
- [x] Requirement trace, local links, version claims, and negative fixtures pass.
- [x] Approved document diff and reviewer sign-off are attached to CYB-34.

The approval record is `docs/evidence/M0-E01-approval-record-2026-08-25.md`.
