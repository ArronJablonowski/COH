# Approval fingerprint v1 compatibility matrix

| Input or change | v1 result | Required action |
|---|---|---|
| Exact verified manifest plus matching positive intent-policy decision | Same fingerprint | Continue to governed approval lifecycle |
| Any manifest field, signature identity, or canonical bytes change | New fingerprint or denial | Re-sign, reevaluate policy, and request new approval |
| Policy decision bytes, actor revision, policy revision, time, outcome, or reason change | New fingerprint or denial | Reevaluate and request new approval |
| Target, exclusion, argument, payload, credential, tool, ROE, validity, nonce, or use count change | New fingerprint | New manifest, policy decision, and approval |
| Unknown/missing fingerprint field or unsupported version | Deny | Use an explicitly qualified reader/version |
| Non-intent, denied, malformed, or approval-not-required policy decision | Deny | No approval fingerprint is issued |
| Cross-organization, tenant, case, actor, manifest, or policy substitution | Deny | Rebuild from matching trusted inputs |
| Exact fingerprint replay | Same identity, not authority | CYB-51 must reject stale/consumed/revoked grant state |
| Expired or future action validity | Deny | Issue a current manifest and repeat policy evaluation |
| Audit append failure | Effective outcome unavailable | Restore audit and retry from the beginning |

No v1 reader fills a missing binding from ambient context, accepts a raw
digest asserted by a workflow/model, weakens canonicalization, or treats a
matching fingerprint as an approval grant.
