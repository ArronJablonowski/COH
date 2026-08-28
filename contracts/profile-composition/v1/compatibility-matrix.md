# Profile composition v1 compatibility and rollback matrix

| Field | Value |
|---|---|
| Stable key | COH-E25-02 / CYB-183 |
| Layer schemas | `coh.profile-layer/v1`, `coh.signed-profile-layer/v1` |
| Output schemas | `coh.resolved-profile/v1`, `coh.profile-inspection/v1` |
| Canonical profile | `COH-CJ-1` |

## Reader and composition decisions

| Input or transition | V1 result | Reason |
|---|---|---|
| Exact v1 schemas, valid current signatures/trust, closed target and parent graph | Accept for deterministic resolution | Qualified V1 path |
| Unknown schema, contract version, member, layer kind, target, feature, limit, or merge row | Deny | Readers never guess semantics |
| Duplicate JSON member, logical identity, signer, bundle ref, permission, endpoint, or ordering identity | Deny | Ambiguity cannot gain identity |
| Same logical layers in a different input order | Emit byte-identical resolved and inspection records | Total order is data-derived |
| Missing baseline, multiple baselines, missing parent, parent mismatch, or cycle | Deny with no partial profile | Layer graph must be closed and acyclic |
| Unsigned, invalid, expired, untrusted, or revoked signer | Deny | Provenance must be current |
| Added endpoint/permission, raised limit, or false-to-true feature | Deny | Overlays only narrow |
| Conflicting deployment profile or offline bundle | Deny | Security posture is exact |
| Capability bundle conflict, ambiguity, cycle, qualification drift, or graph/profile mismatch | Deny | COH-E25-01 remains authoritative |
| Cancellation or timeout | Publish nothing; restart verification from immutable inputs | Partial state has no identity |
| Interrupted pre-publication composition | Discard candidate and recompute | No active revision changed |
| Interrupted activation | Recovery uses the durable maintenance record; never infer success | Activation is a separate state machine |
| Same active revision after restart | Re-verify signatures, trust, revocation, artifacts, and graph | Cached success is not authority |

## Change classification

| Change | Compatibility | Required action |
|---|---|---|
| Documentation clarification with identical accepted bytes and meaning | Patch-compatible | Review and unchanged executable fixtures |
| Add optional member, layer kind, target, feature, limit, or merge rule | Not V1-compatible | New contract version and mixed-reader denial evidence |
| Change ordering, canonicalization, digest domain, signature preimage, or merge meaning | Cryptographically breaking | New major contract, migration, replay, and rollback evidence |
| Raise a bound while preserving semantics | Security-sensitive breaking | New version, resource analysis, policy and security review |
| Remove/rename/retype a field or reinterpret an enum | Breaking | New version and explicit lineage-bearing translation |
| Accept unknown fields, unsigned overlays, implicit defaults, or best-effort providers | Forbidden | Model the meaning explicitly or deny |
| Reuse a removed identity or rewrite historical layer bytes/signatures | Forbidden | Allocate a new identity/revision |

## Upgrade and rollback

| Scenario | Result |
|---|---|
| Current revision advances from its exact predecessor | Recompose and activate only through quiescent maintenance |
| New binary reads a retained exact V1 profile | Accept only after current verification |
| Old binary reads a future schema/layer | Deny; it must not strip fields or fall back |
| Candidate fails before publication | Keep the prior durable active revision; candidate has no authority |
| Candidate fails after maintenance begins | CYB-184 recovery completes reverse unwind or remains safely quiescent |
| Ordinary request selects an older revision | Deny as downgrade |
| Current signed rollback authority selects an older revision | Re-verify it as a new activation attempt; never reuse old graph authority |
| Rollback target depends on revoked signer/provider/artifact | Deny rollback |
| Air-gap verification lacks any required key, revocation snapshot, bundle, SBOM, provenance, policy, validator, or offline feed | Deny offline activation |

## Surface and platform parity

Web, CLI, API, headless, and test paths submit the same typed composition request
to the command composition root and consume the same canonical resolved profile.
Native workstation, native server, and Compose may select different signed layers
but use the same decoder, verifier, ordering, merge, capability resolver, and
inspection encoder. A platform-specific bypass or alternate entrypoint is a
release-blocking architecture violation.
