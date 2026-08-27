# Signed evidence lifecycle v1 compatibility matrix

| Input | V1 behavior | Migration or recovery |
|---|---|---|
| Exact `1.0.0` payload with a recognized V1 schema | Validate strict shape, then semantic and canonical bindings | Continue only after current authority and dependency verification |
| Unknown schema or contract version | Reject without reinterpretation | Install a reader that explicitly supports the version |
| V1 package with `COHEVPKG1`, `compression: none`, exact declared frames and no trailing bytes | Verify completely in the isolated import worker | Publish only after local trust and authority succeed |
| ZIP, TAR, compressed, nested, path-bearing, linked, sparse, device, or extension-bearing input | Reject as unsupported or unsafe | Re-export through the V1 pathless package writer |
| Structurally valid signature from an unknown, stale, expired, or revoked key | Reject; signature conveys no trust or authority | Supply an approved current trust snapshot or re-export with an authorized key |
| Structurally valid package with incomplete custody or audit-checkpoint proof | Report `incomplete`; never import or release | Restore the complete proof and verify again |
| Exact command replay with current authority and intact progress | Verify and resume or return the original receipt | Never duplicate package, case transition, custody link, import, or disposition |
| Idempotency key reused with any changed command or package field | Reject as changed replay | Submit a new request and idempotency identity |
| Interrupted import with some encrypted artifacts published | Keep references hidden and resume the exact package | Verify existing ingestion/custody receipts before advancing |
| Interrupted hold placement | Treat the committed restrictive case state as effective | Append/verify the exact custody record on replay |
| Interrupted hold release | Treat release as operationally incomplete for export/deletion | Repair the exact custody record before consequential work |
| Case tombstone without disposition attestation | Never claim physical deletion | Recover the exact authorized disposition operation |
| Disposition attestation without completed custody/audit proof | Withhold completed result | Replay verifies attestation and repairs the same custody/audit records |
| Pre-V1 export, unsigned bundle, loose artifact set, or foreign lifecycle record | Never grandfather as signed V1 evidence | Re-ingest/re-export through current governed boundaries |
| Rollback to a binary without V1 writers | Preserve and reject unknown V1 mutation | Keep V1 readers/recovery tooling and resume forward |

Compatibility never infers a missing signature, key trust, local policy allow,
approval, custody link, audit checkpoint, legal-hold release, tombstone,
disposition result, or immutable receipt.
