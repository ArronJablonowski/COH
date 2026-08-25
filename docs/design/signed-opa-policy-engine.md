# Signed OPA policy engine

## Decision

COH-E05-02 embeds Open Policy Agent v1.17.0 through its Go compiler, top-down
evaluator, and in-memory storage APIs. COH accepts only the signed policy
profile in `contracts/policy/v1`; it does
not run an OPA server, expose OPA's REST surface, fetch bundles, or enable OPA
management plugins.

This is the first executable authorization component in E05. The canonical
action contract from CYB-52 remains the action identity. OPA decides whether
that exact action may proceed under one current tenant policy. Later approval
and audit leaves consume the immutable decision rather than reconstructing it.

## Existing-boundary inventory

| Boundary | Existing owner | E05-02 use |
|---|---|---|
| Canonical signed action | `internal/domain/actionmanifest` | Verified manifest and exact policy digest/revision input |
| Local and OIDC identity | authenticated transport plus `internal/domain/localidentity` | Fresh actor/scope/revision authority supplied by broker composition |
| Credential rotation/revocation | `internal/broker/credentiallease` | Current policy decision digest is already a lease and dispatch binding |
| Workflow side-effect route | `internal/workflow.ActionAuthority` | Workflow never receives an evaluator or connector |
| Sole action authority | `internal/broker` | Only boundary permitted to compose policy and later dispatch |
| Policy placeholder | `internal/policy.Evaluator` | Replaced with the typed, manifest-bound evaluation port |
| Tamper-evident audit | CYB-49 (future) | Current narrow sink fails closed and is replaced by the final append-only sink |

There was no OPA dependency, bundle contract, loader, active-policy store, or
decision implementation before this leaf.

## Threat assumptions

Bundle bytes, Rego source/data, action requests, workflow state, model output,
and all serialized authority claims are attacker-controlled until independently
verified. The configured signing key, its active revision, broker clock,
authenticated actor snapshot, capability registry results, validator state,
E-stop state, and audit sink are trusted composition inputs. A signed policy is
trusted to express tenant policy but is not trusted to manufacture these
external facts or bypass audit.

The adversary may alter envelope or module bytes, insert duplicate or unknown
JSON fields, replay an old bundle, rotate/revoke a key, cross tenant scope,
exploit ambiguous output, request an unsafe builtin, change an action by one
byte, cancel evaluation, or fail audit. Each path produces no usable allow
decision.

## Load path

1. Reject nil/cancelled context, missing dependencies, inactive/malformed trust
   root, and oversized JSON input.
2. Under a single activation lock, perform bounded unique-key decoding and
   COH-CJ-1 canonicalization of the envelope and nested policy bundle.
3. Verify the declared SHA-256 bundle digest and Ed25519 signature against the
   current out-of-band key ID and revision using the fixed domain separator.
4. Reject unknown fields, invalid metadata, malformed/unsorted modules,
   excessive modules, invalid scope/time/key/revision, and non-object data.
5. Reject cross-tenant replacement and every non-increasing revision.
6. Parse Rego v1 using the closed capability set, compile only
   `data.coh.authz.decision = result`, and retain immutable compiler, query,
   and in-memory data snapshots with strict builtin errors.
7. Append the safe activation event. Only after that succeeds, atomically
   publish the immutable prepared snapshot.

Any failure leaves the prior pointer untouched. Concurrent loads serialize, so
a slower lower revision cannot overwrite a higher one. Evaluations open an
independent read transaction against the immutable snapshot.

## Evaluation path

Each call loads one immutable active snapshot and obtains fresh engine time.
It revalidates current signing authority, bundle validity, verified-manifest
policy binding, tenant/case/actor scope, actor activity, manifest validity,
tool/target/tenant/route registration, capability completeness, validator
qualification, and E-stop before invoking Rego.

OPA receives a newly allocated typed input converted through unique-key JSON.
Caller slices are cloned. The result must bind exactly one `result` value
whose value is exactly the three-field output contract. The engine hashes the
exact JSON input and the final safe decision. Intent and pre-dispatch phases
therefore have distinct decision identities even when policy returns the same
outcome.

The effective outcome is allowed only after the audit sink accepts the result.
Cancellation and timeout use stable public codes; audit receives a bounded
context derived with `context.WithoutCancel` so request cancellation cannot
erase the attempted decision. A fresh call restarts all checks.

## Dependency and upgrade policy

OPA is pinned to v1.17.0. Its transitive module graph and every license digest
are closed CI inputs. An OPA upgrade is a security-boundary change: regenerate
the module/license inventories, compare capabilities, rerun signed/tampered
bundle fixtures and adversarial evaluation traces, run the offline vulnerability
gate, and record a new evidence checkpoint. Semver alone is not approval.

## Follow-on composition

CYB-50 will fingerprint the canonical action bytes together with this decision.
CYB-51 will make grants consumable and revocable. CYB-48 adds T4 dual approval.
CYB-49 replaces the audit port with the hash-chained store. E05 integration then
proves the broker performs `pre_dispatch` evaluation after all fresh checks and
passes only that decision into credential and connector dispatch.
