# CYB-42 deployment-profile validation report

| Field | Value |
|---|---|
| Issue | COH-E04-02 / CYB-42 |
| Requirements | FR-078, FR-079, FR-080, FR-082, NFR-002 |
| Verification date | 2026-08-25 |
| Contract | `coh.deployment-profile/v1` / `1.0.0` |
| Implementation checkpoints | `e46a19e`, `bd662d2`, `4dffa2d`, `d891c65` |
| Qualified declaration checkpoint | `d891c653b877645a073130edf292d880a0157f7b` |
| Review status | Local technical evidence complete |

## Outcome

COH now has a strict, versioned, fail-closed startup-profile validator for
native workstation, native server, and Compose deployments across connected,
restricted-connected, and air-gap modes. It rejects insecure or contradictory
declarations before runtime composition and emits a redacted, digest-bound
decision through a required audit port.

All five frozen valid declarations and all sixteen adversarial mutations passed
their exact expected outcomes. Unit, race, vet, architecture, secret, static,
license, dependency, SBOM, provenance, and the remaining required baseline
stages passed from a clean commit. No unresolved blocking finding remains.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Validate native workstation, native server, Compose, connected, and air-gap profiles | Five versioned fixtures plus semantic matrix tests cover all three deployments and all three connectivity modes | Pass |
| Default-deny actor and scope binding | Configuration change carries organization/actor/revision/previous digest; trusted `AuthoritySnapshot` must match | Pass |
| Secret redaction and fail-closed audit | Contract has no secret-value field; unknown secret input is never echoed; every decision requires `AuditSink`; append failure returns `unavailable` | Pass |
| Replay, tamper, stale state, and revocation | Exact digest/revision replay is idempotent; changed replay, skipped/old revision, wrong lineage, scope mismatch, and inactive actor deny | Pass |
| Invalid input, denial, timeout/cancellation, recovery | Typed results and redacted decisions are tested for each path; immutable input succeeds with a fresh context | Pass |
| Applicable CI and architecture gates | Clean 18-stage baseline; race/vet; 27 packages and zero architecture violations | Pass |
| Required evidence | Frozen denial corpus, audit recorder traces, decision digests, focused verification log, baseline report, design contract, and checksum ledger | Pass |

## Profile behavior

The native workstation declaration requires macOS arm64, SQLite, persistent
Temporal development mode, local authentication and evidence, and loopback-only
services. Any Docker requirement or Compose field is denied. The production
validator imports no host, process, network, runtime, or filesystem-probe
package, so native validation cannot detect or depend on a Docker executable,
daemon, socket, or VM.

The native server declaration requires Linux amd64, PostgreSQL 18, production
Temporal, OIDC, mTLS, a configured evidence store, a private listener, and
distinct control-plane, workflow, and database identities.

Compose requires PostgreSQL 18, production Temporal, OIDC, mTLS, migrations,
validators, a selected provider, and exactly six component image digests. All
profiles deny Docker socket mounts, public database/workflow ports, and secret
values in environment variables.

Connected modes require explicit bounded endpoint references. Air-gap mode
requires zero endpoint, DNS, Internet, telemetry, update, and external-time
routes plus signed packages, OCI archives, policies, validators, SBOMs,
provenance, offline feeds, and offline verification tools.

## Authority, audit, and replay trace

An allowed change is bound to the canonical configuration digest and a trusted
organization/actor snapshot. The initial revision has no predecessor. Later
revisions must increment by one and name the exact current digest. The current
revision with the exact same digest returns `replayed=true`; changed bytes at
that revision do not replay.

Allowed, invalid, denied, canceled, and timed-out requests produce decisions
containing only safe enums, identity metadata, revision, and digests. The audit
test records each decision by value. Missing audit or a backend append error
returns a redacted `unavailable` result and no startup authorization. An
inactive actor returns `actor_revoked`; a mismatched organization or actor
returns `authority_scope_mismatch`.

Profile validation does not grant a consequential-action approval. The trusted
authority snapshot is configuration-change authority, and its allowed/denied
audit decision is the approval/audit evidence applicable to this startup
control. Action policy and approvals remain owned by COH-E05.

## Adversarial corpus

The frozen denial corpus covers:

- native Docker dependency and Docker socket mounting;
- public database exposure and environment secret transport;
- shared server identities;
- floating or extra Compose images, missing migrations, and wrong authentication;
- ephemeral workstation Temporal;
- duplicate endpoint references;
- air-gap DNS/endpoint escape and incomplete offline provenance;
- connected/offline-mode contradiction; and
- unsupported contract version.

Additional strict-input tests deny empty, oversized, malformed, duplicate-key,
unknown-field, and secret-bearing objects without retaining the rejected value.

## Baseline evidence

The clean checkpoint `d891c653b877645a073130edf292d880a0157f7b`
passed all 18 required stages with `quality_gate_promotable=true`. The report
digest is `0004468c23e4352f0fa3c6677ae30d5561e64d1d383104372e08c65338047333`;
the report-file SHA-256 is
`f33be82d7aa4ec139b2811a43fb5384d0c62f63e8764b8bd4628fd9d0b4d2679`.
Provenance records 340 source files, Go 1.26.7 on darwin/arm64, and a clean VCS
state. The focused verification-log SHA-256 is
`54f3f2bcb157eaccbf65783c24f26ddaf44159f11d4583d376236e0aa67d45d4`.

The first baseline attempt correctly denied a deprecated parser API in the
surface test. Commit `d891c65` replaced it with supported per-file parsing; the
focused verifier and complete baseline were then rerun cleanly. No rule or
threshold was weakened.

## Reproduction

```sh
./scripts/verify_deployment_profiles.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- CYB-41 authenticates local actors and implements RBAC; this validator consumes
  but does not manufacture a trusted authority snapshot.
- CYB-43 implements opaque secret references and secret backends.
- CYB-45 implements live credential leases, rotation, and revocation before
  connector/runner dispatch.
- This issue validates declarations. Packaging, actual egress enforcement,
  service startup, and version-specific platform qualification remain later
  implementation and release gates.
- Independent security architecture review remains required before the first
  production release.
