# Skill registry compatibility matrix

| Change | Compatibility | Required action |
|---|---|---|
| Add a new skill version with new immutable bytes | Additive | New manifest identity, predecessor, tests, review, signatures, policy decision, audit, and promotion |
| Change content, resource, permission, tests, threat model, owner, publisher, review, or validity | Authority change | New immutable version; in-place replacement is denied |
| Add an optional or unknown field | Incompatible | New contract version and explicit migration |
| Change canonicalization or a signature/digest domain | Incompatible | New parallel decoder and replay assessment |
| Rotate or revoke a publisher/reviewer key | Immediate current-authority change | Republish or re-review; cached authority never extends access |
| Roll back | Compatible state transition | Signed command may select only the immediate predecessor |
| Revoke | Compatible narrowing | Signed command; resolution stops while immutable bytes remain |
| Re-promote from revoked state | New authority | New manifest version whose predecessor is the revoked current digest |
| Lower an actor's allowed permission set | Compatible narrowing | New access decision; manifest permissions cannot override policy |
| Widen permission or scope | Authority widening | New reviewed version and exact policy/access decisions |
| Reuse an idempotency key with changed input | Incompatible replay | Denied without changing durable state |
| Return raw content, paths, URLs, credentials, or execution handles | Incompatible security boundary | Use a separately reviewed retrieval/execution control |

No compatibility is inferred from matching names, semver text, prior
promotion, successful JSON decoding, or a signature without current authority.
