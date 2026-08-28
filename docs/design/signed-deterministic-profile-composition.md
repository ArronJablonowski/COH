# Signed deterministic profile composition

| Field | Decision |
|---|---|
| Linear issue | CYB-183 / COH-E25-02 |
| Status | V1 contract frozen; implementation follows |
| Public contract | `contracts/profile-composition/v1/` |
| Dependencies | CYB-42 deployment validation; CYB-182 typed capability seams |

## Purpose

COH needs one explainable runtime composition regardless of deployment shape or
operator interface. Ordered signed profile layers turn deployment, connectivity,
surface, site, and overlay choices into one canonical resolved profile. The
same record drives startup validation, capability-graph resolution, inspection,
and later quiescent activation.

This is a configuration compiler, not a plugin loader. It handles immutable
metadata and digests only. It cannot execute code, resolve credentials, approve
actions, dispatch tools, mutate policy, install extensions, or replace any of
the ten reserved authority services enforced by COH-E25-01.

## Trust boundary

Only the command composition root may accept a typed target plus durable layer
references. It loads immutable bytes from a trusted artifact reader, strictly
decodes them, recomputes layer digests, and checks domain-separated Ed25519
signatures against a fresh trust/revocation snapshot. Provider, workflow,
transport, Web, CLI, and API packages cannot construct trusted snapshots or call
the low-level resolver directly. The compiled `ARCH-004` architecture rule also
denies direct profile-composition imports outside the command root, including
imports hidden behind inactive build tags.

The trust snapshot and revision authority are not JSON and contain verification
metadata only. The trust snapshot is bounded to five minutes, exact
organization/environment scope, required signer roles, key purposes/revisions/
validity, and current revocation revisions. The revision authority binds the
exact profile and target to the currently published revision and composition
digest. Initial publication must be revision 1, forward publication must advance
exactly one revision, same-revision replay must reproduce the exact composition
digest, and downgrade requires one current authorization digest bound by exactly
one selected signed layer. Neither object contains a private key, credential,
activation callback, policy evaluator, or execution authority.

## Resolution pipeline

1. Strictly decode every envelope and reject representation ambiguity.
2. Recompute the layer digest and verify every required current signature.
3. Select layers that exactly cover the requested deployment, connectivity,
   platform, and surface tuple.
4. Close parent identities and reject missing parents, digest drift, duplicates,
   multiple baselines, and cycles.
5. Derive the stable total order and apply only the frozen field-specific merge
   rules. Any widening or conflicting exact field denies the profile.
6. Derive the non-circular profile binding digest from the exact target and
   effective security posture, then load exact deployment, policy, and capability
   bundle artifacts by digest.
7. Run deployment-profile validation and COH-E25-01 capability resolution using
   the profile binding digest and current qualification authority.
8. Canonically encode the resolved profile and derive the redacted inspection
   projection. Publish both atomically or publish neither.

No stage uses input array order, filesystem discovery order, map iteration, wall
clock formatting, platform path syntax, or localized output as a tie-breaker.

## Inspection and operator accuracy

Inspection makes configuration provenance visible without exposing sensitive
content. It reports the exact target, ordered layer lineage, versions, layer and
signature-set digests, current trust/revocation revisions, capability definition/
provider/consumer nodes and edges, qualification digests, narrowed limits and
feature states, capability graph digest, composition digest, and inspection
digest.

It intentionally omits endpoint values, secret material, raw deployment config,
public keys and signatures, evidence, prompts, private paths, environment values,
provider callbacks, and mutable runtime state. All access surfaces return the
same canonical inspection bytes, making operator comparisons and automated drift
checks reliable.

## Lifecycle boundary and recovery

Composition is side-effect free. A candidate becomes eligible for activation
only after complete validation. Any security-critical difference from the active
profile requires the durable lifecycle controller to enter quiescence,
stop new admissions, drain or cancel bounded work, publish atomically, and audit
the transition. Live hot reload is always denied.

An interruption before publication discards the candidate. An interruption in
activation is recovered from the durable transition record; restart never infers
that the candidate was active. Rollback is a new verified activation attempt
bound to a current administrative rollback authorization, not reuse of a cached
graph or old signature success.

The transition advances by compare-and-swap through `prepared`, `quiescent`,
`published`, and `active`. Its intent binds a 1–300 second drain/cancel ceiling.
The maintenance gate must attest that admissions are stopped, active work is
zero, and the state is durable before SQLite atomically publishes the active
profile pointer with the transition. Admissions resume only after publication.
Lost responses at every boundary reload and replay the exact phase; restart
reconstructs the same intent from newly verified composition outputs. The
`live_hot_reload` mode denies before persistence or maintenance side effects.

## Implementation sequence

The frozen contract is short task 1. Subsequent tasks implement strict records
and cryptographic verification, deterministic merge and capability resolution,
denial behavior, redacted inspection, durable quiescent activation/recovery,
surface/platform parity and adversarial tests, and final checksummed evidence.
