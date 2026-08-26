# Remote-worker and runner-lease contract v1

This contract freezes the COH-E06-04 boundary for SEC-012, SEC-024, and
SEC-025. Remote workers enroll only through a currently verified mTLS peer and
an Ed25519-signed, freshness-bounded software capability attestation. The
attestation binds organization, tenant, worker, enrollment nonce, transport
identity, certificate fingerprint and revision, attestation key revision,
platform, exact executor/runtime/tool-registry digests, isolation classes,
maximum tier, resource capacity, and network modes.

This is a software attestation contract. It makes no TPM, secure-boot, TEE, or
hardware-root claim. A future hardware proof must use a new version and an
independently reviewed verifier.

Runner leases are private, random, short-lived, single-use broker
capabilities. Serializable requests contain no capability bytes. Each lease is
bound to one actor, case, task, action, target set, tool operation, tier,
isolation class, resource policy, network policy, worker revision, certificate
revision, attestation revision, authorization, policy, approval, and audit
decision. Dispatch atomically consumes the capability before revalidation and
before invoking the authenticated runner callback.

The control plane rejects T4, unknown or unsorted capabilities, authority
expansion, stale or tampered attestations, non-mTLS remote identities,
certificate/key rollback, isolation or capacity mismatches, replay, expiry,
cancellation, E-stop, revocation, and audit failure. Revoking a worker,
certificate, or attestation immediately revokes its outstanding leases.

`local_socket_authenticated` is a trusted transport variant for local internal
services. It requires an absolute socket path, no world permissions, matching
owner/peer UID and GID, a peer PID, and platform-authenticated peer
credentials. Remote-worker enrollment always rejects this variant and
requires `remote_mtls`.

Compatibility is additive only inside optional decision output fields. Any
change to a required request, binding, signature domain, capability meaning,
or lease claim rule requires a new schema and contract version.
