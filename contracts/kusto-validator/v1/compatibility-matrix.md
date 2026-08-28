# Kusto validator v1 compatibility matrix

| Change or condition | V1 behavior | Migration / recovery |
|---|---|---|
| Exact same contract, registry, helper, package closure, runtime, RID, schema, policy, and request | Compatible deterministic replay after current authority checks | Return the same digest-bound result and audit proof |
| Unknown or duplicate JSON field, trailing document, reordered/duplicate set | Deny | Re-encode through the current typed writer |
| Contract schema or canonicalization change | Breaking | Publish a new schema major and dual-read only through an approved migration |
| Kusto.Language, .NET SDK/runtime, package closure, RID, artifact, formatter, or diagnostic drift | Incompatible | Build, sign, attest, and qualify a new helper identity |
| Operator/function/prohibited registry or limit change | Incompatible even when additive | Publish a new registry/validator version and rerun the adversarial corpus |
| Schema expired, changed, substituted, or from another source/workspace/scope | Deny | Repeat CYB-97 qualification and issue a fresh request |
| Helper unavailable, timeout, cancellation, crash, or malformed/tampered output | No accepted result | Destroy staged state; retry only with current authority and verified artifact |
| Audit unavailable after deterministic validation | Withhold success | Exact replay repairs/verifies the same audit append before release |
| Manifest, publisher, policy, capability, schema, or attestation revoked | Immediate deny; retained result unusable | Re-enable only through ordinary signed admission and qualification |
| Rollback requested | Disable operation and revoke affected retained plans | Admit the prior separately signed version and rerun conformance before enablement |

Unknown upstream syntax is never inherited. There is no floating package,
compatible-version range, unsigned fallback, cached authority fallback, or
automatic downgrade.
