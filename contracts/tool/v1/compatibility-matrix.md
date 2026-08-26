# Signed tool registry compatibility matrix

| Change | Compatibility | Required action |
|---|---|---|
| Add a tool name or new semantic version | Additive registry entry | New reviewed and signed manifest |
| Change artifact, operation, input field, tier, isolation, credential, resource, network, cancellation, retry, review, or validity binding | New authority | New manifest identity, review, signature, and prepared actions |
| Increase tool or operation tier ceiling | Authority widening | New review and signed manifest; runtime policy cannot perform it |
| Lower runtime policy ceiling | Compatible narrowing | New policy decision; no manifest widening |
| Add an optional object name or unknown input type | Incompatible | New contract version and explicit migration |
| Changed canonicalization or signature domain | Incompatible | New envelope schema and signature contract |
| Unknown publisher key revision or inactive/unapproved publisher | Denied | Resolve current approved publisher authority or republish |
| Same name/version with different canonical envelope bytes | Conflict | Publish a new tool version; in-place replacement is forbidden |
| Manifest contract major-version change | Incompatible | Parallel decoder, migration/replay assessment, and qualification |
| Unknown manifest, envelope, operation, tier, isolation, network, or capability field | Denied | Update through reviewed versioned change control |

No compatibility is inferred from successful JSON decoding, semver text, or
publisher identity alone. The exact schema, canonical bytes, digest, review,
signature, and current authority must all verify.
