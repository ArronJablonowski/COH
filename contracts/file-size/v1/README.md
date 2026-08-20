# File-size policy contract v1

This bundle belongs to COH-E02-03 / CYB-38 and traces NFR-016, NFR-017,
NFR-018, and EVAL-027.

`ci/file-size-policy.json` is the canonical policy instance. The executable
reader accepts only `coh.file-size-policy/v1` version `1.0.0`, rejects duplicate,
unknown, case-variant, trailing, malformed, oversized, or non-UTF-8 input, and
requires the locked 500-line warning, 800-line hard limit, 300-line script
limit, and 150–400 normal target.

## Scope and counting

The checker evaluates the complete sorted set returned by Git's cached and
untracked-visible source inventory. Physical lines are newline-delimited lines,
with a final unterminated line counted once. Script classification takes
precedence over production classification. Binary classified production or
script input is denied; unrelated binary input is skipped and counted.

The checker snapshots before and after evaluation and denies identity, byte,
mode, digest, path, Git revision, or membership drift. Repository metadata,
source ancestors, policy input, evidence input, and output parents cannot be
symlinks. Git hooks, fsmonitor, global configuration, replacement objects, and
optional locks are disabled in its narrow source adapter.

## Governed exceptions

Each exception names one canonical repository path and is bound to category,
owner, normalized justification, strict UTC expiry date, `CYB-N` tracking
issue, lowercase SHA-256 content digest, and an approved maximum. Non-script
categories also require a generator identity and a matching generated header
within the first five physical lines. Exceptions are sorted and unique;
missing, stale, expired, digest-mismatched, misclassified, over-limit, or
headerless entries deny the scan. Script exceptions may approve 301–800 lines;
other categories may approve 801–1,000,000 lines.

## Evidence and compatibility

`coh.file-size-report/v1` is canonical JSON with a self-digest, policy and
exception digests, complete source identity, typed outcome, stable findings,
and CYB/requirement trace. Publication uses a same-directory, no-replace hard
link commit and directory sync; an existing or racing destination is preserved.

There is no persisted production-data migration in v1. Policy or report
version changes require a new versioned reader, schema, canonical fixtures,
compatibility decision, both Go lanes, and fresh evidence. A compatible-looking
unknown version is denied; thresholds cannot be weakened through configuration.

| Fixture | Expected result |
|---|---|
| `fixtures/valid/file-size-policy.canonical.json` | Exact accepted v1 policy |
| `fixtures/invalid/unknown-field.json` | `invalid_input` |
| `fixtures/invalid/weakened-threshold.json` | `denied` |

Run the native wrapper with all mutable state on trusted storage:

```sh
COH_NATIVE_STORAGE_ROOT=/Users/aj_lobster/Developer \
COH_TOOLCHAIN_ROOT=/Users/aj_lobster/Developer/COH-toolchains \
scripts/check_file_sizes.sh
```
