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

## Lifecycle compatibility

| Stored or requested state | Lifecycle v2 result | Required action |
|---|---|---|
| Provisional pre-CYB-51 approval payload | Never active authority | Re-request under `coh.approval-lifecycle/v2` |
| `coh.approval-lifecycle/v1` record | Never T4 authority; no stable-principal enrollment proof | Re-request under lifecycle v2 |
| Exact idempotency replay | Original commit result | Return the already committed revision |
| Same idempotency key with changed input | Conflict | Use a new key only for a new intended operation |
| Stale expected revision | Conflict | Reload and re-authorize from fresh state |
| Changed fingerprint, scope, requestor, validity, threshold, or use binding | Deny | Create a new signed action, policy decision, fingerprint, and request |
| Duplicate or self grant | Deny and audit | Obtain a distinct eligible approver |
| Expired, rejected, consumed, or revoked record | Terminal denial | Create a new approval request from fresh authority |
| Unknown field, state, operation, or contract version | Deny | Use an explicitly qualified reader/version |
