# Signed pySigma helper v1 compatibility matrix

| Change or condition | V1 behavior | Migration / recovery |
|---|---|---|
| Exact contract, profile, helper, package closure, runtime, backend, mapping, schema, policy, and request | Compatible deterministic replay after current authority checks | Return the same digest-bound result and audit proof |
| Unknown/duplicate JSON field, trailing document, reordered/duplicate set, ambiguous map | Deny | Re-encode through the current typed writer |
| Contract, canonicalization, Sigma profile, diagnostic taxonomy, or limit change | Breaking | Publish a new contract/profile identity and approved migration |
| pySigma, backend, CPython, PyInstaller, package closure, RID, or artifact drift | Incompatible | Build, sign, attest, and qualify a new helper identity |
| Mapping or discovered target schema changed, stale, or substituted | `needs_mapping` or deny | Review a new mapping revision and recompile against fresh schema |
| Unsupported Sigma construct or target/backend combination | `unsupported`; no native query | Add only through a reviewed profile/backend revision and corpus |
| Security Onion requested | Unavailable in v1; no OpenSearch fallback | Implement and qualify a direct bounded Sigma-to-OQL lowering path |
| Helper unavailable, timeout, cancellation, crash, stderr, or malformed/tampered output | No compiled result | Destroy staged state; retry only with current authority and verified artifact |
| Native target validator rejects generated text | Result remains untrusted and unusable | Correct mapping/backend/profile; never widen or skip validation |
| Manifest, publisher, policy, capability, schema, mapping, qualification, or attestation revoked | Immediate deny; retained result unusable | Re-enable only through ordinary signed admission and qualification |
| Rollback requested | Disable operation and revoke affected retained results | Admit prior separately signed version and rerun full conformance |

There is no compatible version range, ambient plugin discovery, pipeline YAML,
external/template source, publication-format fallback, `collect_errors`,
skip-unsupported behavior, automatic downgrade, or unsigned fallback.
