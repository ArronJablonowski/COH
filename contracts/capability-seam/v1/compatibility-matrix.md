# Typed capability seam v1 compatibility matrix

| Change or mixed state | v1 behavior | Required path |
|---|---|---|
| Identical canonical declarations | Same bundle digest | Exact replay may reuse verified durable evidence after current revocation checks |
| Member order or insignificant whitespace changes | Same canonical bytes and digest | Accept after strict decoding |
| Unknown field, schema version, or contract version | Deny whole bundle | Publish a new reviewed contract version |
| Capability version changes | Deny exact-version mismatch | New definition, provider qualification, consumer declaration, and composition revision |
| Provider artifact, owner, scope, permission, lifecycle, or profile changes | Prior qualification is invalid | Qualify the exact new tuple and sign a new composition revision |
| Missing or duplicate definition/provider/consumer identity | Deny whole graph | Repair declarations; no partial resolution |
| Required dependency is absent or cyclic | Deny whole graph | Publish an acyclic closed declaration set |
| Optional dependency is absent | Omit its edge deterministically | Consumer must tolerate absence under its own contract |
| Consumer scope or permissions widen | Deny | New signed profile revision, policy decision, audit, and qualification as applicable |
| Qualification expires or is revoked | Deny before publication and use | Obtain current qualification; never revive the old record |
| Authority service declared replaceable | Deny | Authority services remain compiled and non-replaceable |
| Data-plane provider requests direct execution access | Deny | Submit a typed broker intent |
| Live security-critical composition change | Deny | Enter a quiescent maintenance transition and fully revalidate |
| Restart with only a serialized resolved graph | Deny | Rebuild from signed durable declarations and profile |
| Rollback to an older but trusted revision | Deny by default | Explicit signed rollback lineage, current policy, revocation checks, audit, and re-resolution |

No row permits an old reader to reinterpret unknown data, an input document to
widen compiled authority, or a provider registration to grant action authority.
