# Go workspace contract compatibility matrix

| Field | Value |
|---|---|
| Issue | COH-E02-01 / CYB-32 |
| Current writer | `coh.architecture/v1`, contract `1.0.0` |
| Current reader | `archcheck` built with Go `1.26.7` |
| Status | Normative |

## Reader decisions

| Input | v1 reader behavior | Rationale |
|---|---|---|
| Schema `coh.architecture/v1`, contract `1.0.x` | Accept if strict schema and locked policy pass | Patch releases cannot add fields or widen edges |
| Contract `1.1.x` | Deny as unsupported | Minor versions may add compatible-looking semantics that require qualification |
| Contract `2.x` | Deny as unsupported | Major versions may break graph meaning |
| Unknown schema | Deny as unsupported | No schema guessing or conversion |
| Unknown JSON field | Deny as invalid | Prevent ignored security-relevant policy |
| Changed root or `may_import` set in v1 | Deny as policy weakening | JSON configuration cannot expand compiled authority |
| Missing or duplicate boundary/root | Deny as invalid | Classification must be complete and unambiguous |
| Canonicalization other than `COH-JSON-C14N-1` | Deny as unsupported | Digests must have one interpretation |
| Module other than `github.com/ArronJablonowski/COH` | Deny as invalid | Prevent checking an unintended import namespace |
| Go baseline other than `1.26.7` | Deny as unsupported | NFR-026 promotion requires qualification evidence |
| Root `go.mod` module/Go/toolchain drift or replacement | Deny | Prevent local-import relabeling and dependency redirection |
| Root `go.work` extra use, replacement, or baseline drift | Deny | Only the reviewed root module may enter the workspace graph |
| Nested non-ignored `go.mod` or `go.work` | Deny | Root traversal cannot prove imports in another module |
| Platform/tag-only forbidden import | Deny | All source files are parsed in addition to the active compiler graph |

## Change classification

| Change | Required contract change | Required evidence |
|---|---|---|
| Documentation-only wording outside executable contract | None | Link and documentation review |
| Purpose wording with unchanged behavior | Patch | Canonical fixture, digest, contract tests |
| Bug fix that tightens an existing edge | Patch, or minor if downstream impact is material | Positive/negative graph corpus and migration note |
| New boundary or source root | Minor | Architecture review, schema/reader update, mixed-version denial test |
| New allowed import edge | Minor and security review | Threat-model trace and explicit bypass-negative tests |
| Removed/renamed boundary or changed module/schema/canonicalization identity after the first canonical commit | Major unless a staged migration preserves both | Migration tool, rollback plan, old/new fixtures |
| Go baseline promotion | Contract change plus NFR-026 qualification | Replay, dependency, race, platform, and architecture suites |

## Initial-baseline identity correction

The change from the draft module path
`github.com/cyber-operations-harness/coh` to
`github.com/ArronJablonowski/COH` was a correction to the initial baseline, not a
released migration. At the correction point the repository had no first commit,
public tag, released bytes, deployed reader, persisted contract data, or public
compatibility promise. The superseded contract, fixture, and evidence bytes
existed only as local draft evidence.

This narrow exception ends when the first canonical repository commit is
created. From that commit onward, a module-path, schema-identity, or
canonicalization-identity change follows the major-version migration path,
including old/new fixtures, explicit compatibility tests, rollback evidence,
and denial of unqualified mixed versions. A later change cannot be classified
as another initial-baseline correction merely because it has not yet been
released as a tag.

## Compatibility obligations

- Writers emit only the exact version they implement and retain its canonical
  fixture and digest in release evidence.
- Readers fail closed on versions newer than their qualified range.
- No best-effort downgrade, field stripping, or automatic policy migration is
  permitted.
- A migration produces a new canonical artifact; it never overwrites the input.
- Rollback restores the previous reader and contract together.
- Mixed versions are denied until an explicit compatibility test proves the
  exact pair safe.
- The first canonical commit freezes the module, schema, and canonicalization
  identities for v1; later identity changes require the major migration path.
- Go 1.27 can run in a qualification lane but cannot update the baseline field
  or release claim until all required suites pass.
- Every verdict records its actual Go version, GOOS, GOARCH, build tags, VCS
  state, Go-source digest, combined source/module/workspace input digest, and
  import-graph digest; support cannot be inferred from the contract alone.

## Current qualification

| Pair | Status |
|---|---|
| Reader `1.0`, contract `1.0.0`, Go `1.26.7` | Supported by COH-E02-01 evidence |
| Reader `1.0`, contract `1.0.x` later patch | Structurally accepted; release support requires patch evidence |
| Reader `1.0`, contract `>=1.1.0` | Denied |
| Reader `1.0`, Go `1.27.x` | Qualification only; not a support claim |
| Pre-first-commit draft module corrected to `github.com/ArronJablonowski/COH` | Accepted as the initial baseline; all local evidence regenerated |
| Any reader, module path changed after the first canonical commit | Denied until a major migration is approved |
