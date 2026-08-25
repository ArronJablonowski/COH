# Signed OPA policy v1 compatibility matrix

| Input or change | v1 result | Required action |
|---|---|---|
| Exact canonical envelope and bundle, current Ed25519 key/revision, entrypoint, modules, and data | Verify, compile, audit, atomically activate | Qualified v1 path |
| Unsigned, tampered, digest-mismatched, duplicate-key, unknown-field, or wrong-key envelope | Deny | Rebuild and sign through approved policy release |
| Same or lower revision | Deny | Issue a strictly higher tenant-scoped revision |
| Failed replacement after a qualified activation | Keep last-known-good active | Repair candidate; never partially activate |
| Organization or tenant changes on one engine | Deny | Compose a separate tenant-scoped engine |
| Added metadata, input, or output field | Deny | New contract version and mixed-reader qualification |
| Rego v0, alternate entrypoint, malformed/unsorted module path, Wasm, plan, archive, or delta input | Deny | New explicit profile and security review |
| Newly requested builtin | Compile denial | Review determinism/side effects, version contract, and qualify |
| OPA patch/minor update | Not silently compatible | Dependency, capability, fixture, adversarial, license, and vulnerability review |
| Signer rotation | Old active bundle evaluates only while exact old authority remains current | Higher bundle revision signed by the new active key; old actions become stale |
| Bundle expiration or signer revocation | Deny every evaluation immediately | Activate a current higher revision under current authority |
| Intent decision reused at dispatch | Deny by composition contract | Reevaluate phase `pre_dispatch` and consume that decision |
| Missing/unknown tool, target, tenant, route, tier, validator, or capability field | Deny before Rego can allow | Qualify and register the exact capability through change control |
| Undefined, extra-field, wrong-type, or multi-result policy output | Deny | Correct the signed policy and increment revision |
| Audit append failure | Effective outcome `unavailable` | Restore audit and reevaluate from the beginning |

The v1 engine never fetches policy, follows an embedded URL, accepts embedded
authority, enables an unknown builtin, downgrades Rego, or uses an older
decision after activation state changes.
