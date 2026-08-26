# Signed and reviewed skill registry v1

| Field | Value |
|---|---|
| Issue | COH-E09-01 / CYB-70 |
| Requirements | FR-042, FR-043, SEC-018 |
| Manifest | `coh.skill-manifest/v1` / `1.0.0` |
| Envelope | `coh.signed-skill-manifest/v1` / `1.0.0` |
| Change command | `coh.signed-skill-change/v1` / `1.0.0` |
| Canonicalization | COH-CJ-1 |
| Signatures | Ed25519 with separate publisher, reviewer, and owner domains |

A skill is available to production agents only when its exact immutable
manifest is publisher-signed, independently reviewer-signed, policy-allowed,
audited, and durably promoted. A file on disk, a model request, an embedded
prompt, or an earlier approval is not promotion.

The manifest binds the skill name and strict semantic version to its owner,
publisher, content and resource digests, finite resource metadata, sorted
permissions, test suite and test evidence, threat model, predecessor, review,
and validity window. It contains no content bytes, secret, credential, path,
URL, connector, executor, policy source, or generic callback.

Publisher signatures use
`COH-SIGNED-SKILL-MANIFEST-V1\0 || canonical_manifest`. Every listed
reviewer must be distinct from the owner and publisher and signs
`COH-REVIEWED-SKILL-MANIFEST-V1\0 || canonical_manifest`. Promotion,
rollback, and revocation are separately owner-signed over
`COH-SIGNED-SKILL-CHANGE-V1\0 || canonical_command`. Verification resolves
fresh active approved authority and exact key and approval revisions; identity
inside a document cannot grant authority to its own signature.

Promotion requires an exact, current policy decision whose recomputed digest
binds organization, tenant, case, task, actor, action, skill, and target
manifest. The fail-closed audit receipt is incorporated into registry
provenance before one optimistic transaction makes the state and any new
immutable version durable. Same-key changed replay, stale revision, byte drift,
audit failure, or version collision leaves the prior state authoritative.

Rollback selects only the immediately preceding immutable digest. Revocation
keeps the signed bytes and lineage but stops new resolution immediately. A
fresh promotion is required to leave revoked state; no old bytes are rewritten.

Resolution requires an exact current manifest digest, permission, actor and
organization/tenant/case/task scope, plus a current access decision with a
recomputed digest. The registry re-verifies publisher and reviewer authority,
signatures, validity, durable state provenance, and audit before returning
anything. The result contains only copied immutable digests and resource
metadata. Content retrieval and execution remain separate guarded operations.

Policy and access decision digests exclude their own `decision_digest` field
and use the domains `COH-SKILL-POLICY-DECISION-V1\0` and
`COH-SKILL-ACCESS-DECISION-V1\0` over the remaining canonical record.
Registry provenance similarly excludes its own digest and chains the previous
provenance digest.

All object fields are required. Go decoders reject duplicate, unknown,
missing, trailing, oversized, malformed, unsupported-version, noncanonical
timestamp, unsorted-set, or semantically invalid input.

## Progressive discovery

`skill-discovery.schema.json` freezes COH-E09-02 / FR-042. Discovery is three
separate default-deny operations: compact search, exact detail expansion, and
resolution of one exact signed resource to an immutable artifact reference.
Every request binds request and idempotency identity, organization, tenant,
case, task, actor, policy digest, required permission, and deadline.

The compact page contains only skill name, semantic version, current manifest
digest, and registry provenance. It never contains content or resource
metadata. Its opaque cursor binds the query, scope, policy, permission, and
durable promoted-catalog snapshot. A changed snapshot makes the cursor stale.

Details require the exact manifest digest returned by compact search and cause
the signed registry to recheck current promotion, validity, publisher and
reviewer authority, policy scope, permission, and provenance. Resource
resolution repeats those checks and accepts one exact resource name and digest.
The detail request must bind a durable case/task-scoped compact result containing
that manifest; resource resolution must bind a durable detail result containing
that descriptor. A caller cannot skip or substitute either parent phase.
The retriever can return only a matching immutable `ArtifactRef`; discovery has
no HTTP, shell, filesystem-write, connector, executor, model, or generic
callback capability.

Each phase has its own recomputed decision digest and durable idempotency
record. Exact replay returns an owned copy of the prior result. Same-key changed
replay, manifest or resource drift, stale catalog state, malformed authority,
cancellation, timeout, or storage ambiguity fails closed.
