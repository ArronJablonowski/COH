# Deployment-profile validation

## Purpose

CYB-42 implements the startup security declaration for COH's native and Compose
profiles. The contract is versioned as `coh.deployment-profile/v1` / `1.0.0`.
It is evaluated before services may be composed, but a passing declaration is
not a platform-support or production-qualification claim.

The validator is deterministic and side-effect-free except for its required
audit port. It never probes a host, searches for Docker, opens a socket, reads
an environment variable, loads a credential, starts a service, or selects a
fallback. This separation is how Docker can remain optional for native use.

## Change authority and audit

Each declaration names an organization, administrator actor, positive revision,
and previous configuration digest. The caller supplies an authenticated
`AuthoritySnapshot`; the validator does not trust identity fields merely
because they occur in JSON.

The following checks occur before an allowed result is returned:

1. bounded unique-key JSON decoding and exact contract version;
2. profile, service, isolation, connectivity, and offline-bundle invariants;
3. actor and organization equality with the trusted snapshot;
4. active actor status;
5. monotonic revision and exact previous-digest lineage; and
6. durable append of the redacted decision through `AuditSink`.

The decision contains actor/scope identifiers, revision, deployment and
connectivity enums, safe reason codes, the canonical configuration digest, and
its own deterministic digest. It contains no endpoint value, image name,
credential, secret, environment value, or backend error. Audit failure returns
`unavailable`; startup cannot continue without an audit record.

An exact current revision and configuration digest is an idempotent replay.
The same revision with changed bytes, a skipped/old revision, a wrong previous
digest, a different scope, or an inactive actor is denied.

## Profile matrix

| Declaration | Required invariants |
|---|---|
| Native workstation | macOS arm64, SQLite, persistent Temporal development mode, local authentication/evidence, loopback-only, no Docker requirement or Compose fields |
| Native server | Linux amd64, PostgreSQL 18, production Temporal, OIDC, mTLS, configured evidence store, private listener, three distinct service identities, no Docker requirement |
| Compose | Supported host/architecture declaration, PostgreSQL 18, production Temporal, OIDC, mTLS, complete six-image digest inventory, migrations, validators, selected provider |

All profiles deny a Docker socket mount, public database or workflow port, and
secret values in environment variables. Native profiles also deny any declared
Docker dependency. Compose requires Docker explicitly but cannot weaken the
native path or use the socket as a control boundary.

## Connectivity matrix

| Mode | Required invariants |
|---|---|
| Connected | One or more bounded configuration references identify permitted endpoints; DNS and Internet routing are explicit |
| Restricted connected | Same explicit references; later network enforcement restricts actual egress to the configured allowlist |
| Air-gapped | No endpoint references, DNS, Internet, telemetry, updates, or external time; complete signed-package, OCI, policy, validator, SBOM, provenance, feed, and offline-verifier inventory |

The validator checks declarations, not network behavior. The required 24-hour
zero-egress qualification remains a release/platform test and cannot be
inferred from a valid air-gap configuration.

## Failure and recovery

| Condition | Result |
|---|---|
| Empty, oversized, malformed, duplicate-key, unknown-field, or unsupported contract | `invalid_input`; safe redacted decision |
| Insecure or contradictory profile | `denied`; exact stable reason code |
| Scope mismatch, revoked actor, stale revision, or lineage mismatch | `denied`; no composition authorization |
| Context canceled or expired | `canceled` or `timeout`; a new context may retry immutable input |
| Audit missing or append failure | `unavailable`; backend detail is not retained |
| Exact current revision and digest | Allowed with `replayed=true`; no new configuration identity is invented |

## Verification

The frozen corpus contains five valid declarations and sixteen denial
mutations. Tests cover valid native/Compose and connected/air-gap combinations,
strict parsing, secret redaction, default denial, scope, revocation, replay,
tamper, stale state, audit failure, cancellation, timeout, and clean recovery.
An import-surface test proves production validator files cannot import host,
process, network, runtime, or filesystem-probe packages.

Run:

```sh
./scripts/verify_deployment_profiles.sh
```

## Residual scope

- CYB-41 authenticates local actors and produces the trusted identity/RBAC
  snapshot; this validator only binds and enforces the supplied snapshot.
- CYB-43 implements opaque secret references and backends. Endpoint references
  here are identifiers, never secret values.
- CYB-45 implements live credential lease rotation and revocation.
- Packaging, actual network enforcement, service startup, and platform
  qualification belong to later implementation and release gates.
