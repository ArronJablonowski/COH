# Signed deterministic profile composition v1

| Field | Value |
|---|---|
| Stable key | COH-E25-02 / CYB-183 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Signatures | Ed25519 over a domain-separated canonical layer |
| Requirements | NFR-003, NFR-019, SEC-018, SEC-033, SEC-034, EVAL-029 |

This contract composes signed, ordered, data-only profile layers into one exact
resolved profile and one redacted inspection record. It is shared by native
workstation, native server, Compose, connected, restricted, air-gap, Web, CLI,
API, headless, and test operation. A layer describes configuration; it never
contains or grants an approval, credential, lease, callback, executor, connector,
policy authority, or action authority.

## Records

| Schema | Purpose |
|---|---|
| `signed-profile-layer.schema.json` | Canonical layer payload, exact targets, bounded contributions, lineage, rollback binding, and publisher/reviewer signatures |
| `resolved-profile.schema.json` | Exact target, ordered qualified layer bindings, effective narrowed settings, capability-graph digest, and composition digest |
| `profile-inspection.schema.json` | One redacted Web/CLI/API-safe projection of lineage, graph nodes/edges, qualifications, limits, feature states, and digests |
| `profile-activation-transition.schema.json` | Durable CAS-advanced startup/maintenance transition through prepared, quiescent, published, and active phases |
| `active-profile.schema.json` | Atomically published profile pointer bound to the transition, resolved profile, graph, and inspection digests |
| `fixtures/layer.signed.valid.json` | Deterministically signed native-workstation baseline layer |
| `fixtures/denial-corpus.json` | Executable strict-decoding, signature, trust, revocation, secret-field, ordering, and cancellation denials |

All objects are schema-closed. Readers also reject duplicate JSON names,
trailing values, invalid UTF-8, excessive size/depth, unsorted set-like arrays,
duplicate logical identities, noncanonical timestamps, and unsupported versions.

## Canonical identity and signatures

The layer digest is:

```text
sha256("COH-PROFILE-LAYER-V1\0" || COH-CJ-1(layer))
```

Each signature verifies:

```text
Ed25519.Sign(key, "COH-SIGNED-PROFILE-LAYER-V1\0" || layer_digest_bytes)
```

The outer envelope is not the signed preimage. Every publisher and reviewer
identity, key revision, trust purpose, validity interval, and current revocation
revision is resolved from the trusted composition root. Signature order is
canonical by role, signer identity, key identity, and key revision. Duplicate
signers, an absent publisher, unknown keys, expired keys, revoked keys, invalid
signatures, or a trust snapshot older than five minutes deny composition.
The snapshot environment must exactly cover the layer's deployment selector;
a workstation trust decision cannot qualify a native-server or Compose layer.

Signing proves provenance only. It does not authorize activation or operation.

## Target selection and total order

A composition request names exactly one deployment kind, connectivity mode,
platform, and access surface. Every selected layer must include all four values
in its target selectors. Exactly one baseline layer is required. Layers form a
closed acyclic parent graph; every parent identity, revision, and digest must be
present and exact.

The total order is stable topological order followed by ascending precedence,
kind order (`baseline`, `deployment`, `connectivity`, `surface`, `site`,
`overlay`), name, layer ID, revision, and digest. Equal ordering identities or
an ordering that places a child before a parent deny the complete composition.
Input array order never changes output.

## Merge semantics

The baseline supplies a complete value for every setting. Later layers can only
narrow it. No implicit default or generic JSON merge exists.

| Field | V1 merge rule |
|---|---|
| Deployment profile | Exact identity across all layers; any difference denies |
| Capability and policy bundle refs | Append by exact ID/revision/digest, then canonical identity order; conflicting reuse denies |
| Endpoint references | Set intersection; an overlay cannot introduce an endpoint absent from every ancestor |
| Permissions | Set intersection; an overlay cannot introduce a permission absent from every ancestor |
| Numeric limits | Component-wise minimum |
| Feature states | Logical AND; `false` cannot become `true` later |
| Offline bundle digest | Exact empty-or-one digest; air-gap requires one exact common digest, non-air-gap requires empty |

The selected capability bundles are decoded and joined as declarations before
the COH-E25-01 resolver runs. Definition/provider/consumer conflicts, ambiguous
providers, dependency cycles, widening, invalid qualification, or a graph whose
profile digest differs from the profile binding digest deny publication.

## Digests and redacted inspection

Provider qualification uses a non-circular profile binding digest over the exact
target, deployment-profile reference, policy-bundle references, narrowed
endpoints, permissions, limits, features, and offline-bundle digest:

```text
sha256("COH-PROFILE-BINDING-V1\0" || COH-CJ-1(profile binding))
```

It deliberately excludes capability-bundle digests, capability graph, and layer
lineage because those artifacts themselves bind this value. The final
composition digest below binds the complete lineage, capability artifacts, and
resolved graph, so this exclusion cannot hide provenance or alter final identity.

The resolved composition digest is:

```text
sha256("COH-RESOLVED-PROFILE-V1\0" || COH-CJ-1(resolved profile without composition_digest))
```

The inspection digest uses the same rule with domain
`COH-PROFILE-INSPECTION-V1\0` and `inspection_digest` omitted. Inspection is a
derived view, never an input. It lists stable IDs, versions, owner module names,
qualification state, graph edges, effective limits/feature states, layer and
signature-set digests, trust/revocation revisions, profile binding, and final digests.
Graph node IDs, module paths, access modes, and full SemVer values are preserved
exactly; the projection never rewrites an identifier to make it displayable.

There is no field for credentials, secret values, raw evidence, prompt content,
private paths, endpoints, raw configuration, signatures, public keys, executable
payloads, or mutable objects. Web, CLI, and API emit byte-identical canonical
inspection bytes for the same resolved profile.

## Rollback and lifecycle boundary

A normal revision must bind the currently active predecessor digest and advance
monotonically. A lower or previously active revision is a downgrade and denies
unless `rollback_authorization_digest` binds a current, separately signed,
scope-exact administrative rollback decision. Rollback re-verifies every layer,
key, trust record, revocation, artifact, policy bundle, deployment profile, and
capability qualification; a prior successful graph is not authority.

Composition itself does not activate configuration. Security-critical changes require
a durable quiescent maintenance transition. Live hot reload, model-controlled
composition, untrusted overlay injection, and activation from Web/API/CLI parsing
paths are forbidden. CYB-183 owns profile composition and durable profile
publication; CYB-184 owns transactional extension activation and reverse unwind.

The activation controller persists intent before requesting quiescence. Its
maintenance gate must stop admissions, drain or boundedly cancel active work,
within the signed activation intent's 1–300 second ceiling and return a durable
zero-work attestation. SQLite atomically replaces the
active pointer and advances the transition to `published`; admissions resume
only afterward. A restart reloads the exact phase and requires freshly verified
profile and inspection inputs with the same intent. Lost responses at every
durable boundary replay forward without inferring success or publishing twice.

See `compatibility-matrix.md` for mixed-version and recovery decisions.
