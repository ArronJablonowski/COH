# Canonical signed action v1 compatibility matrix

| Input or change | v1 reader result | Required action |
|---|---|---|
| Exact manifest/envelope schema, version, canonical bytes, and Ed25519 signature | Accept after current signer authority succeeds | Qualified v1 path |
| Same logical object with different member order or whitespace | Decode to identical canonical bytes, but retain only canonical output | No authority attaches to source representation |
| Unsorted or duplicate schema-declared set | Deny | Writer must submit canonical semantic order |
| Duplicate key, trailing data, invalid UTF-8, excessive size/depth, float, exponent, or negative zero | Deny | Correct input; no partial result survives |
| Unknown field, version, algorithm, or action tier | Deny | Explicitly version and qualify the contract |
| Syntactically valid but unregistered credential class, tool, action, target, or execution zone | Contract preserves exact token; policy must default-deny | Register through signed policy/capability change control; never infer support |
| Added optional field | Not automatically compatible | Mixed-reader tests and capability negotiation; otherwise new version |
| Added required field or tighter accepted bound | Breaking | New schema version and migration/replay assessment |
| Removed, renamed, retyped, or reinterpreted field | Breaking | New schema version and explicit lineage-preserving translation |
| Changed canonicalization or signature domain | Cryptographically breaking | New canonical profile, schema major version, and new signatures |
| Changed policy/ROE/credential/tool/payload/target/argument/time/use binding | New action identity | New manifest, signature, policy decision, and approval |
| Unknown signer key revision or inactive signer | Deny | Re-sign with current eligible key after reauthorization |
| Timeout or cancellation | No published result | Retry immutable input from the beginning |
| Migration | Preserve original signed bytes | Emit a separately signed new-version manifest with lineage |

The v1 reader never silently drops fields, downgrades versions, substitutes an
older policy, fills authority from surrounding context, or treats an approval
for one digest as approval for another.
