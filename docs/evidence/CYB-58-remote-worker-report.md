# CYB-58 remote-worker enrollment and lease verification report

| Field | Value |
|---|---|
| Issue | COH-E06-04 / CYB-58 |
| Requirements | SEC-012, SEC-024, SEC-025 |
| Verification date | 2026-08-26 |
| Implementation checkpoint | `bfce11f7c12f47d4cd233030d5fbb65989df333f` |
| Aggregate result | Pass |

## Outcome

Remote workers now enroll only through a verified TLS 1.3 peer identity and a
fresh Ed25519-signed software capability attestation. Enrollment binds the
organization, tenant, worker ID, exact SPIFFE URI SAN, certificate fingerprint
and revision, one-time nonce, attestation public-key digest and revision,
platform, executor/runtime/tool-registry digests, T0-through-T3 isolation
capabilities, resource ceilings, and network modes. T4 and local-transport
downgrades are denied.

Runner dispatch requires a private random lease that is short-lived,
single-use, stored only by digest, and bound to the complete actor/action/tool,
worker, isolation, resource, network, policy, approval, and audit snapshot. The
broker atomically claims and destroys the capability, revalidates the current
mTLS peer and worker revision, durably audits authorization, and only then
invokes the authenticated callback with a capability-free envelope.

Worker, certificate, attestation, or lease revocation is immediate. Worker
rotation atomically revokes outstanding leases. Replay, stale authority,
tamper, expiration, cancellation, E-stop, audit failure, store races, callback
failure, and revision rollback fail closed without restoring capability bytes.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Remote workers enroll with mTLS identity and capability attestation; dispatch requires a short-lived runner lease and matching isolation | TLS-state adapter, signed-attestation verifier, enrollment/lease stores, atomic `Use`, exact isolation/resource/network tests | Pass |
| Default-deny actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation handling | Canonical schemas and strict decoders; decision digests; audit-failure revocation; replay, tamper, rotation, and revocation tests | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain provenance without bypass | Typed error contract; invalid/denied/canceled/timeout cases; callback failure audit; same-store broker recovery; consumed-lease replay denial | Pass |
| Success/failure automation passes applicable CI, race, architecture, secret, license, dependency, and size gates | Dedicated verifier and all 18 clean baseline stages at `bfce11f` | Pass |
| Evidence cross-references COH-E06-04 and SEC-012/024/025 | This report, design traceability table, retained logs, clean baseline, and checksum manifest | Pass |

## Canonical contracts

`contracts/worker/v1` freezes eight strict JSON schemas for capability
attestation, signed envelope, enrollment, lease issuance, dispatch, revocation,
and redacted decisions. Unknown or duplicate fields are rejected by the Go
decoders and canonicalizer. Serializable request and decision types contain no
lease token, private key, secret value, or capability bytes. A public-surface
test also proves that only the lease ID is exported from the in-memory handle.

The attestation signature covers canonical bytes under the domain separator
`COH-REMOTE-WORKER-CAPABILITY-V1\\0`. The trusted control plane selects the
Ed25519 public key, key ID/revision, expected nonce, worker scope, and current
transport identity; request data cannot alter those facts. Attestations are
valid for at most five minutes and must be current at verification and lease
use.

This is explicitly software capability attestation. It is not evidence of a
TPM, measured boot, secure boot, TEE, or physical-host isolation.

## mTLS and local peer identity

`internal/transport/workeridentity.FromVerifiedTLS` accepts only a completed
TLS 1.3 connection with a verified peer chain. The selected leaf must be the
verified leaf, currently valid, and contain exactly the scope-bound worker
SPIFFE URI SAN. The adapter computes the certificate SHA-256 fingerprint from
DER and a transport-identity digest from organization, tenant, worker,
fingerprint, monotonic certificate revision, and URI SAN.

Enrollment and use revalidate freshness, certificate lifetime, fingerprint,
revision, identity digest, and URI SAN. Certificate rotation changes the worker
revision and revokes old leases; rollback, fingerprint substitution without a
revision increase, or revision increase with a reused fingerprint is denied.

For SEC-025, `local_socket_authenticated` requires an absolute path, nonzero
mode with no world permission, matching owner/peer UID and GID, a peer PID, and
platform-authenticated peer credentials. Remote enrollment always rejects this
variant and requires mTLS.

## Enrollment and rotation

Enrollment verifies exact request/authority scope, current mTLS state,
one-time nonce, signature, digest, lifetime, and capability vocabulary before
creating an immutable worker revision. Exact idempotency can return the same
live revision, while changed content under the same key conflicts. Expected
revision prevents concurrent lost updates.

Certificate and attestation-key revisions cannot decrease. The stored
attestation public-key digest prevents same-revision key substitution; a key
revision increase must use new key material. A revoked worker cannot be
silently reactivated by enrollment. Enrollment audit failure immediately
revokes the just-created worker and all associated leases.

## Runner lease, dispatch, and recovery

Issuance binds organization, tenant, case, actor and actor revision, task,
action, sorted targets, exact tool/version/digest/registry and operation,
required tier/isolation, concrete resource request and policy digest, network
mode and policy digest, worker/certificate/attestation revisions, and current
authorization, policy, and approval decisions. Requested capacity must be
within the signed worker ceiling. Expiry is the earliest of request TTL,
broker maximum, or attestation expiry.

The broker generates 32 random bytes and persists only SHA-256. Reissuing the
same idempotency key never returns another capability. Store claim is atomic;
only one concurrent user can win. The capability is destroyed before current
authority and worker revalidation, so denial or callback failure cannot be
replayed. A pre-canceled request can safely retry without a claim, while
cancellation/E-stop after claim consumes the lease.

An allowed dispatch decision is durably appended before the callback. Callback
success or failure produces a second completion decision. If pre-dispatch audit
fails, the callback is never reached. Reconstructing a broker over the same
store preserves revoked/consumed state and cannot recreate capability bytes.

The included concurrency-safe memory store is for a single control-plane
process. A multi-replica deployment must provide a durable implementation of
the same atomic store interface and conservatively treat uncertain claims as
consumed; the design does not claim that process memory is cross-replica
durability.

## Adversarial verification

Automated tests cover:

- unknown/duplicate fields, wrong contracts, signature/digest tamper, nonce and
  certificate mismatch, stale/expired attestation, T4 and unknown capability;
- unverified TLS chain, TLS below 1.3, incomplete handshake, wrong URI SAN,
  invalid certificate lifetime, non-mTLS and local downgrade;
- exact and changed enrollment replay, concurrent revision conflict,
  certificate/key rollback or substitution, audit-triggered revocation;
- policy/approval/actor/task/E-stop denials, isolation/tier/registry/resource/
  network mismatch, entropy/store/audit failures;
- lease token tamper, duplicate issuance, expiry, direct and transitive
  revocation, certificate rotation, concurrent claim, callback failure,
  canceled/timeout context, and restart/replay recovery; and
- audit redaction, decision digest sensitivity, private handle surface, race,
  cross-platform compilation, architecture, and file-size gates.

## Focused verification

The exact clean checkpoint passed `scripts/verify_remote_workers.sh` with:

```text
remote-worker summary: attestation=ed25519-software freshness=5m remote_transport=mtls local_transport=authenticated-socket tiers=T0-T3 t4=denied enrollment=immutable+rotatable lease=random+short-lived+single-use claim=atomic isolation=exact resources=bounded network=bound revocation=immediate audit=fail-closed failures=0
```

The retained log is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/remote-worker.p4bkRJ/remote-worker.log`
with SHA-256
`9b72b21a53da9043cdd432ce43df826632b991570af3a5a3659ea1a1e6cafb7d`.
It includes unit, three repeated runs, race, vet, Linux amd64 and Windows amd64
broker compilation, schema/secret checks, 51-package architecture verification
with zero violations, file-size enforcement, and diff checks. Provenance names
`bfce11f`, `modified:false`, Go 1.26.7, and darwin/arm64.

## Clean baseline

The exact clean checkpoint passed all 18 required baseline stages with
`quality_gate_promotable=true` and `vcs_modified=false`. Evidence is retained
at `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.oio5wH`.

The embedded report digest is
`bfd166a6d3237649048f3ddc040efcc5372774964a46a3019a5888d754f02496`;
the report-file SHA-256 is
`7a1f58b94f171b0e2f254b6f81b2a538c1753b646cfe09b10347997e8fce68c1`.
Provenance records 680 source files, source digest
`973521ee078edbc2fb7a696f6ab63cbb6c1f66a533213b9911bfe0c2a48b4e63`,
Go 1.26.7 on darwin/arm64, 51 architecture packages with zero violations, and
183 approved modules with zero vulnerabilities.

## Reproduction

```sh
./scripts/verify_remote_workers.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- COH-E06-05 / CYB-57 integrates native, OCI, and remote execution with the
  complete containment and E-stop path.
- Deployment work must supply a durable multi-replica store before enabling
  more than one control-plane writer; the current implementation fails closed
  rather than claiming that capability.
- Independent security architecture review remains required before the first
  production release under CYB-173.
