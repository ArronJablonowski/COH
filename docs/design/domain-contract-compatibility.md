# Domain contract v1 compatibility matrix

| Field | Value |
|---|---|
| Issue | COH-E03-01 / CYB-36 |
| Reader | `internal/helper/domaincontract.Validator` |
| Schema | `coh.domain/v1` |
| Canonical profile | `COH-CJ-1` |
| Source checkpoint | `7c253ac` |
| Status | Draft — blocked by COH-E01/COH-E02 and reviewer approval |

## Reader decisions

| Input or change | v1 reader result | Reason |
|---|---|---|
| Exact `coh.domain/v1`, registered kind, valid envelope and payload | Accept and emit canonical bytes | This is the qualified v1 path |
| Unknown schema identity or future domain version | Deny | Readers never guess, downgrade, or translate versions |
| Unknown kind | Deny | Kind support is an exact advertised capability |
| Duplicate key, trailing data, invalid UTF-8, excessive size or depth | Deny before publication | Ambiguous or unbounded representations cannot gain identity |
| Unknown envelope or payload field | Deny | Ignored fields could carry security-relevant meaning |
| Missing required field or value outside a schema bound | Deny | Validation cannot invent a default or widen policy |
| `case` with `case_id != id` | Deny | A case owns its own authorization/storage boundary |
| Required case-scoped kind with null `case_id` | Deny | Case authority cannot be inferred from surrounding state |
| `model` or `skill` with null `case_id` | Accept if all other rules pass | These records may represent tenant catalog capabilities |
| Same immutable input after timeout or cancellation | Revalidate from the beginning | No partial object or hidden recovery state is published |
| Same valid logical object with different member order/whitespace | Accept to identical canonical bytes | COH-CJ-1 removes representation ambiguity |
| Floating point, exponent, or negative zero | Deny | v1 canonical numbers are base-10 integers only |

## Change classification

| Proposed change | Compatibility | Required action |
|---|---|---|
| Documentation clarification with identical accepted bytes and meaning | Patch-compatible | Link review and unchanged executable fixtures |
| Add optional field | Not automatically compatible | Prove old-reader safe denial/preservation, add capability negotiation and mixed-reader fixtures |
| Add registered kind | Additive registry revision | Prove old-reader unknown-kind denial and new-reader positive/negative fixtures |
| Add required field or tighten an accepted bound | Breaking for existing writers | New schema version, migration assessment, old/new replay fixtures |
| Remove, rename, retype, or reinterpret a field | Breaking | New schema version and explicit translation with lineage |
| Change case-boundary mode | Security-sensitive breaking change | Product/security approval, migration, replay, denial, and rollback evidence |
| Change canonical ordering, escaping, number, timestamp, UUID, or digest rules | Canonical-profile breaking change | New canonical profile and schema major version |
| Accept unknown fields or versions | Forbidden | Model and qualify the extension explicitly |
| Reuse a removed field or kind identity | Forbidden | Allocate a new identity |

## Mixed-version and migration rules

- Readers advertise exact schema and kind support; writers use only a mutually
  supported pair.
- Original canonical bytes and version remain immutable. Migration creates a
  new object with lineage to the source rather than rewriting custody history.
- A timeout, cancellation, or failed migration publishes no replacement object.
- Rollback restores the prior reader and contract together. It does not strip
  fields or relabel newer bytes as v1.
- API `/api/v1` support does not imply support for every domain schema or kind.
- The draft case-boundary modes require COH-E01 approval before they become a
  stable product promise.

## Current qualification

| Pair | Status |
|---|---|
| Current reader + exact `coh.domain/v1` + 16 registered kinds | Locally verified at `7c253ac` |
| Current reader + unknown kind | Denied |
| Current reader + any schema other than exact `coh.domain/v1` | Denied |
| Older reader + a future optional field or kind | Denied until explicit mixed-version qualification |
| Any reader + changed COH-CJ-1 semantics | Unsupported; requires a new profile/version |

