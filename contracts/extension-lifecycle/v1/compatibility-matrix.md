# Extension lifecycle v1 compatibility and recovery matrix

| Field | Value |
|---|---|
| Stable key | COH-E25-03 / CYB-184 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |

## Reader and admission decisions

| Input or transition | V1 result | Reason |
|---|---|---|
| Exact v1 manifest, current signatures/review/promotion/qualification/policy/profile/audit/E-stop | Prepare transaction | Fully qualified path |
| Unknown schema, version, field, kind, phase, registration role, permission, scope, or limit | Deny | Readers never infer lifecycle meaning |
| Duplicate JSON member, signer, reviewer, dependency, permission, scope, or registration identity | Deny | Ambiguity cannot gain identity or order |
| Unsigned, invalid, expired, untrusted, unreviewed, unpromoted, unqualified, or revoked manifest | Deny before effects | Current authority is mandatory |
| Production agent or model requests lifecycle change | Deny before persistence | Lifecycle administration is not a model capability |
| Reserved control-plane capability or owner root is declared | Deny | Extensions are data-plane only |
| Requested permission, scope, resource, profile, or dependency exceeds the signed declaration | Deny | Runtime inputs can only narrow |
| E-stop is tripped/unknown/stale or audit is unavailable | Deny or remain safely quiescent | Stop and audit are mandatory guards |
| Cancellation or timeout before first effect | Persist no registration; transition may terminate inactive | No capability was published |
| Cancellation or failure after one or more effects | Persist `unwinding`; revoke in strict reverse order | Partial capability cannot leak |
| Same idempotency key and byte-identical input | Return the exact durable result or continue its phase | Replay is convergent |
| Same idempotency key with changed input | Deny without state change | Intent substitution is forbidden |
| Receipt/handle owner, ordinal, scope, generation, or registry revision differs | Deny and remain not active | Revocation cannot cross ownership |
| Live hot activation or replacement | Deny | Startup or quiescent maintenance only |

## Interruption and restart

| Durable point | Recovery decision |
|---|---|
| Intent verified but no transition persisted | Re-verify from immutable input; no effect exists |
| `prepared` persisted | Re-verify all current authority, then apply registration zero |
| Effect committed but receipt response lost | Resolve by exact idempotency identity; persist the same receipt, never duplicate |
| Receipt persisted during activation | Continue at the next ordinal only |
| `unwinding` persisted | Revoke at the durable reverse cursor; exact replay is idempotent |
| Active pointer published but response lost | Return the exact active record after current verification |
| Deactivation admission closed | Keep admission closed; drain/cancel from durable work inventory |
| Work drained/canceled | Record terminal outcomes before revoking registrations |
| All registrations revoked | Commit terminal audit, then atomically remove active pointer |
| Terminal audit committed but response lost | Return the exact inactive terminal record |
| Corrupt, missing, or ambiguous transition/receipt/manifest | Deny activation and preserve quarantine/quiescence for operator recovery |

## Upgrade and rollback

| Scenario | Result |
|---|---|
| New version binds the exact active predecessor and advances lifecycle revision | Quiescent deactivation followed by a fresh activation transaction |
| Candidate activation fails before publication | Reverse-unwind candidate effects; prior active version remains authoritative |
| Candidate fails after prior version is deactivated | Complete candidate unwind and remain safely inactive; never silently resurrect |
| Ordinary intent selects an older manifest/version | Deny as downgrade |
| Current separately signed rollback authority selects the immediate retained predecessor | Re-verify and activate as a new transaction under current authority |
| Rollback target has revoked signer, review, promotion, qualification, artifact, policy, or dependency | Deny rollback |
| New binary reads retained exact v1 records | Accept only after current verification and phase validation |
| Old binary reads future schema or unknown phase | Deny; never strip fields or fall back |
| Air-gap activation lacks an exact offline key/revocation/policy/qualification/SBOM/provenance/audit bundle | Deny offline activation |

## Change classification

| Change | Compatibility | Required action |
|---|---|---|
| Documentation clarification with identical accepted bytes and meaning | Patch-compatible | Review and unchanged fixtures |
| Add optional member, extension kind, role, phase, permission, scope, or effect | Not v1-compatible | New contract version and mixed-reader denial evidence |
| Change canonicalization, digest/signature domain, ordering, or reverse-unwind semantics | Cryptographically breaking | New major version, migration, replay, crash, and rollback evidence |
| Raise a resource, duration, registration, or dependency bound | Security-sensitive breaking | New version, resource analysis, policy, and security review |
| Remove/rename/retype a field or reinterpret an enum | Breaking | New version and explicit lineage-bearing translation |
| Accept unsigned input, serialized callback, best-effort unwind, or ownerless registration | Forbidden | Model the effect as signed data or deny it |
| Reuse an extension/registration identity for different bytes or ownership | Forbidden | Allocate a new identity/version |

No compatibility is inferred from a matching name, SemVer string, earlier
success, cached authority, process memory, callback identity, or an audit record
without matching durable lifecycle state.
