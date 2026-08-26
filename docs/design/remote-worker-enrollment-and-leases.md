# Remote-worker enrollment and runner leases

## Decision

CYB-58 introduces a broker-owned boundary in `internal/broker/remoteworker`
and canonical contracts in `internal/domain/remoteworker` and
`contracts/worker/v1`. A caller cannot enroll a worker by asserting identity,
construct a trusted worker record, mint a lease, provide a lease token in a
serializable request, or call a runner before the broker has durably audited
and atomically consumed the corresponding capability.

The initial store is process-local and concurrency-safe. It is suitable for a
single control-plane process and deterministic recovery tests. Multi-replica
deployment requires a durable store that preserves the same atomic enrollment,
idempotency, claim, and revocation interfaces; it must not share the memory
store between replicas by convention.

## Transport identity

Remote enrollment and dispatch require trusted `remote_mtls` state from the
transport adapter. The state binds an identity digest, certificate fingerprint
and monotonic revision, validity interval, SPIFFE URI SAN, and a fresh
observation. It is accepted only when mutual TLS was actually verified and the
certificate is currently valid. A request has no field capable of asserting
these facts.

`internal/transport/workeridentity.FromVerifiedTLS` derives this state from a
completed TLS 1.3 connection with a verified peer chain and exactly one
scope-bound worker SPIFFE URI SAN. It computes the certificate fingerprint
from the leaf DER and the transport-identity digest from the complete scope,
worker, fingerprint, certificate revision, and URI binding.

The transport contract also defines `local_socket_authenticated` for SEC-025.
That variant requires an absolute path, a nonzero restrictive mode with no
world bits, matching socket-owner and authenticated-peer UID/GID, a peer PID,
and explicit platform support for peer authentication. Remote enrollment
rejects this variant to prevent an mTLS downgrade.

## Capability attestation

The worker signs canonical JSON with Ed25519 and the domain separator
`COH-REMOTE-WORKER-CAPABILITY-V1\\0`. The trusted enrollment authority selects
the public key, key ID and revision, expected one-time enrollment nonce,
worker, tenant, and current mTLS identity. The signed statement repeats every
binding and additionally covers platform, executor/runtime/tool-registry
digests, isolation classes, maximum T0-T3 tier, resource ceilings, network
modes, issuance, and expiry. Statements are valid for at most five minutes;
T4 and unknown capability values are unrepresentable.

This is signed software inventory, not remote hardware attestation. No code or
documentation may interpret it as proof of TPM state, secure boot, measured
boot, a TEE, or physical-host isolation.

## Enrollment and rotation

Enrollment validates the public request, fresh authority snapshot, exact
scope, mTLS identity, signature, nonce, and freshness before creating an
immutable revision. Idempotency is exact: an identical live revision can be
replayed, while changed content under the same key conflicts. Rotation requires
the caller's expected current worker revision and disallows certificate or
attestation-key revision rollback. A changed certificate fingerprint or
transport identity requires a higher certificate revision; a higher
certificate revision must not reuse the fingerprint. Revoked records cannot be
silently reactivated through enrollment.

Every result is redacted and audited. If audit append fails after enrollment,
the new worker record and all of its leases are immediately revoked and the
operation returns unavailable.

## Runner lease and dispatch

Issuance revalidates the current worker record and binds actor, case, task,
action and sorted targets; tool name/version/digest and operation; required
tier and exact isolation; concrete resource request plus its policy digest;
network mode plus its policy digest; worker/certificate/attestation revisions;
and authorization, policy, approval, and audit authority. Requested capacity
must fit the signed worker ceiling. Lease expiry is the earliest of the
requested TTL, broker maximum, or attestation expiry.

The broker generates 32 random capability bytes, stores only SHA-256, and
returns an in-memory handle. Exact issuance replay never yields a second
handle. Dispatch first atomically claims the digest, destroys the handle,
revalidates task/E-stop/actor/decisions/mTLS/worker state and exact isolation,
and durably audits authorization. Only then does it invoke the authenticated
runner callback with a capability-free dispatch envelope. Callback completion
or failure receives a separate audit decision. A consumed lease is never
restored after callback, cancellation, timeout, or process recovery.

## Revocation and recovery

Lease revocation is immediate. Worker, certificate, or attestation revocation
marks the worker inactive and revokes all outstanding leases under the same
store lock. Rotation makes older lease snapshots stale even if an explicit
revocation races. On restart, a durable implementation must conservatively
treat uncertain claims as consumed; availability recovery cannot recreate a
bearer capability or permit replay.

## Traceability

| Requirement | Enforcement |
|---|---|
| SEC-012 | Random short-lived single-use runner lease; exact scope; digest-only storage; atomic claim; immediate revocation |
| SEC-024 | Fresh verified mTLS at enrollment and dispatch; certificate fingerprint/revision/validity/SAN binding; rotation invalidates old leases |
| SEC-025 | Restrictive authenticated local-socket identity contract; remote enrollment rejects local downgrade |
| COH-E06-04 | Signed capability enrollment plus matching isolation/resource/network dispatch and redacted fail-closed decisions |
