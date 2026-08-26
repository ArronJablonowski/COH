# Signed tool registry

| Field | Value |
|---|---|
| Issue | COH-E06-01 / CYB-53 |
| Requirements | SEC-005, SEC-018 |
| Manifest | `coh.tool-manifest/v1` / `1.0.0` |
| Signature | Ed25519, domain-separated over COH-CJ-1 manifest bytes |
| Registry identity | Exact tool name and version |

## Purpose

The tool registry is the immutable reviewed capability catalog between broker
policy and every later native, OCI, or remote executor. A tool is not known
because code exists on disk, a model names it, a provider advertises it, or a
binary answers a version command. It is known only when the exact artifact and
operations are present in a current reviewed manifest signed by a currently
approved publisher.

The package is security-neutral domain code. It has no filesystem, process,
network, logging, credential, policy-engine, connector, runner, or workflow
surface. Composition supplies publisher authority and time from trusted
boundaries.

## Immutable bindings

A manifest binds:

- UUIDv7 manifest, publisher, review, and reviewer identities;
- exact tool name, semantic version, and SHA-256 artifact digest;
- tool-wide maximum action tier;
- approved review revision, threat-model digest, and review time;
- exclusive validity window of at most 366 days; and
- a sorted, unique, non-empty operation set.

Each operation binds its exact name and typed input fields; signed baseline and
maximum tiers; isolation and credential classes; wall-clock, CPU, memory,
output, ephemeral-storage, process, and open-file limits; network mode,
protocols, DNS behavior, and connection bound; plus cancellation and retry
semantics.

Typed inputs are a deliberately finite v1 vocabulary: boolean, bounded integer
or duration, bounded string, UUID, digest, timestamp, and bounded string/digest
lists. Unknown or nested generic JSON is not silently admitted. Raw arguments,
targets, payloads, secrets, and credentials remain action-specific and are not
registry metadata.

## Admission and publisher authority

The decoder rejects duplicate, missing, unknown, or case-variant names before
Go zero values can hide them. It canonicalizes the complete manifest with
COH-CJ-1 and computes the immutable digest. Signature verification requires:

- the exact v1 envelope and Ed25519 algorithm;
- digest equality in constant time;
- manifest, envelope, and current authority publisher equality;
- exact current key identity and revision;
- an active publisher with a positive current approval revision; and
- a valid domain-separated signature.

The registry admits only currently valid manifests. Name/version is immutable:
an exact retry recovers the existing admission, while any byte change conflicts
and leaves the last valid snapshot untouched. A manifest UUID cannot be reused
for another registry identity.

## Resolution and revocation

Every resolution supplies a fresh publisher authority. The registry re-verifies
the stored canonical envelope and current validity instead of trusting admission
forever. Publisher revocation, approval rollback, key rotation, key removal,
expiry, signature change, and requested artifact-digest mismatch deny without a
restart.

The returned verified envelope and operation capability own copies of all
mutable bytes and slices. No caller can mutate the registry snapshot through a
returned value.

## Tier monotonicity

The signed operation baseline is the minimum control tier. Deterministic context
may require a stricter tier, but cannot classify below that baseline. The signed
operation and tool ceilings are upper capability bounds. Runtime policy may
provide the same or a lower ceiling; a higher value is an attempted authority
expansion and is denied.

Resolution therefore requires:

`signed baseline <= required tier <= min(tool ceiling, operation ceiling, runtime ceiling)`

Policy narrowing below the required tier denies the operation. Increasing a
tool or operation ceiling requires a new manifest version, security review, and
publisher signature.

## Isolation and fail-closed controls

Native-restricted operations are capped at T2. OCI and ordinary remote
isolation are capped at T3. T4 requires the dedicated isolation class,
cooperative cancellation, `never` retry semantics, bounded target/control
network behavior, and all later COH-E19 controls. Every network profile forbids
public Internet and metadata access; exact target addresses arrive only through
the separately signed action manifest.

Cancellation and timeout before admission or resolution make no registry
change. Invalid or conflicting admission cannot evict a valid entry. The
registry contains no fallback to an older schema, unsigned manifest, cached
publisher approval, inferred operation, or elevated policy ceiling.

## Compatibility and follow-on use

The executable compatibility matrix is in
`contracts/tool/v1/compatibility-matrix.md`. COH-E06-02 through COH-E06-04 must
resolve the exact tool reference and consume the resulting capability before
loading any artifact. They must independently enforce the signed resource,
network, filesystem, credential, cancellation, and retry bounds. COH-E06-05
adds independent E-stop revocation.
