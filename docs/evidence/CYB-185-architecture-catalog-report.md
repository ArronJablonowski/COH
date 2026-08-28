# CYB-185 generated architecture catalog evidence

| Field | Evidence |
|---|---|
| Stable key | COH-E25-05 / CYB-185 |
| Requirements | NFR-019, NFR-026, NFR-027, EVAL-004, EVAL-029 |
| Implementation revision | `cadc7b72ccb491686754e41a93b32b47784c30da` |
| Baseline outcome | Passed; promotable; clean VCS snapshot |
| Quality report | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.TtBAOk/quality-report.json` |
| Quality report SHA-256 | `7eb5877eb8d8f301b5be6fb175edeacae30b0537ee5885549fa1b4fbd55d1bde` |
| Embedded report digest | `582c075aa161ed65486eee20431a9755ead69bc84068fcfb39f09786ec3ed7a1` |

## Catalog results

| Catalog | Records | Bound sources | Catalog digest | File SHA-256 |
|---|---:|---:|---|---|
| Application entrypoints | 9 | 1,315 | `sha256:c18b70e667e03c9cba32f730d6d7321f1164e4aeaea2a390ca197b59f27f5b3e` | `3925126fbcf89a49e7d6c81220d9f543feb887870581193dbad96059d4d8e2cd` |
| Capability graph | 14 | 5 | `sha256:88b5e6d497a5f3f15704642673151883f3a0a856bb9947e39dacb1ffd65a7963` | `cfa20b6f3a0d781d5e1ce45dad8599b0d3ab024d40d31c628c8f13a4b97e0121` |
| Configuration | 17 | 5 | `sha256:79b828bb0e99d38b62f93aea930e7cf8bd7b5469a8667eccbe291f4d1164d72f` | `7f0bc10b81489be7d6d25809aa88f33ae493b495766f787a10b7ad6ccc4f2209` |
| Event routes | 3 | 4 | `sha256:b6eb5e51ff2710a4972d224fdcf9c9d40ebbe3cf0cc50131ffb564593ae00202` | `f9e6cc166f4ac3046683438d0d04d1e42e2f45c412b86f1e71578b15a51a27ee` |
| Durable model-surface events | 1 | 5 | `sha256:ffda67e3f3362c5cdab14bec1f2f06bd4af9b45e12a347d0630a264081a796a8` | `32c8affb4d1f5902fef77da93a7936c09c63e6819fad624bf8575d66067d2a67` |
| Module dependencies | 405 | 1,316 | `sha256:1b7bd27185c62d1615840b2aa9bfc7587c94ed6d00487ad73d89470153b50034` | `3c4e2d40fd362c23def05a9dd748f864f9f38fb4930af2372a31e16c05675377` |

The capability catalog contains the resolved model-inference graph plus all ten
compiled protected-authority records. The dependency catalog contains 119 Go
package records and 286 local import edges. Every Go source below `cmd` and
`internal` is digest-bound into the dependency and entrypoint inventories.

## Conformance and mutation proof

The release-blocking architecture stage regenerated all six catalogs twice in
separate temporary directories, compared the two runs byte-for-byte, compared
them to checked-in evidence, validated the closed envelope, redaction policy,
offline documentation links, 8 MiB file bound, and 131,072-record bound, and
then ran the adversarial mutation suite.

Mutation coverage denied orphan definitions, providers, consumers and edges;
capability cycles; model-visible records without durable projection rules;
unexpected `package main` launch paths; CGo and forbidden dynamic plugin or
interpreter loaders; sensitive publication attributes; and canonical/digest
tampering. The existing architecture checker additionally reported 121
packages, zero undeclared or unclassified dependency edges, and zero
composition/model-provider authority bypasses.

## Full assurance result

All 18 required baseline stages passed at the clean implementation revision:
format, file-size, workflow, secret-worktree, secret-history, architecture,
quality-contract, vet, static-analysis, unit, race, fuzz-seed, license,
dependency, SBOM, supply-chain, secret-evidence, and provenance. The supply-chain
stage independently rebuilt the release bundle and reported
`reproducible=true`, manifest SHA-256
`969082fa445d000ee041c9d70f90f30436a7c4b3224345aecdcac4130f28a71b`,
and archive SHA-256
`6e5c955fc26c69fa03f8b446a10f05338f4692bd0b498a2a79e9e062195c36d3`.

## Acceptance conclusion

COH-E25-05 is satisfied. Catalog generation and conformance are deterministic,
publication-safe, checksummed, and release-blocking. No unresolved blocking or
non-blocking finding remains from this implementation review.
