# CYB-32 Go workspace contract verification report

| Field | Value |
|---|---|
| Issue | COH-E02-01 / CYB-32 |
| Requirements | NFR-019, NFR-026; SEC-002 alignment |
| Verification date | 2026-08-19 |
| Workspace | `/Volumes/Untitled/Codex/COH` |
| Module | `github.com/ArronJablonowski/COH` |
| Contract version | `coh.architecture/v1` / `1.0.0` |
| Contract digest | `ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904` |
| Graph digest | `8291b1f1292184ba0fa057faa82f6599c9bfefb6472938e060dab5f6798b4230` |
| Source digest | `b126f90120e5a644e212d0cc34fdfb443da48d39deade616cf11ebffbf609754` (58 Go files) |
| Input digest | `5696b5433659bafd83e0dcc65e41d2ee1c2754102253759781977f2b098adce1` (58 Go files plus `go.mod` and `go.work`) |
| Executable report digest | `96aad791524305e54ab815767088c5bd4295dac37f474456eb614a959d3e4530` |
| Review status | Independent technical re-review granted; no findings remain |

## Refresh reason and result

This evidence was regenerated after a pre-first-commit correction to the
canonical GitHub module identity, the addition of the CYB-33 quality-gate
packages, and the independently reviewed type-aware broker capability-surface
guard. The previous report described the superseded local-draft
`github.com/cyber-operations-harness/coh` module and a 13-package,
26-source-file graph. It is superseded by this report.

This was not a released migration. At correction time there was no repository
commit, public tag, released byte sequence, deployed reader, persisted contract
data, or public compatibility promise. The superseded bytes were local evidence
only. The correction therefore establishes the initial v1 identity rather than
changing an identity already offered to a consumer. As documented in the
compatibility matrix, the narrow exception expires with the first canonical
commit; any later module, schema, or canonicalization identity change must use
the major-version migration path.

The current executable architecture check is **allowed**: all 15 packages are
classified, the live import graph has zero violations, and the report records
the current 58-file source set and 60-file input set. Three consecutive JSON
report generations were byte-identical.

The repository remains in an unborn, modified Git state. The executable report
records `vcs_revision=unborn` and `vcs_modified=true`; it does not imply release
eligibility or a reviewed commit.

## Delivered evidence

- Schema bundle: [`contracts/architecture/v1`](../../contracts/architecture/v1/README.md)
- Canonical fixture:
  [`workspace-contract.canonical.json`](../../contracts/architecture/v1/fixtures/valid/workspace-contract.canonical.json)
- Compatibility matrix:
  [`go-workspace-compatibility.md`](../design/go-workspace-compatibility.md)
- Executable allowed report:
  [`CYB-32-architecture-report.json`](CYB-32-architecture-report.json)
- Deterministic artifact ledger: `CYB-32-artifacts.sha256`

## Toolchain and storage evidence

The exact toolchain was
`/Volumes/Untitled/Codex/toolchains/go1.26.7/bin/go`, which reported
`go version go1.26.7 darwin/arm64`. The repository and all mutable Go paths used
for the canonical verification were on the external SSD:

```text
COH_TOOLCHAIN_ROOT=/Volumes/Untitled/Codex/toolchains
GOCACHE=/Volumes/Untitled/Codex/toolchains/cache/go1.26.7/build
GOMODCACHE=/Volumes/Untitled/Codex/toolchains/cache/go1.26.7/modules
GOPATH=/Volumes/Untitled/Codex/toolchains/gopath/go1.26.7
GOTMPDIR=/Volumes/Untitled/Codex/toolchains/tmp/go1.26.7
GOTOOLCHAIN=local
GOENV=off
GOTELEMETRY=off
GOFLAGS=-mod=readonly
```

## Verification commands and results

### Exact contract suite

Command:

```sh
scripts/test_go_contract.sh
```

Result: PASS, exit `0`.

- `gofmt -l cmd internal`: no unformatted files.
- `go vet ./...`: pass.
- `go test ./...`: pass across 15 packages.
- `go test -race ./...`: pass across 15 packages.
- Live architecture graph: allowed, 15 packages, zero violations.
- Canonical fixture: byte content matches after the suite's text-newline
  normalization.
- End-to-end `1ns` timeout: exit `130`; the canceled JSON retains contract and
  runtime provenance with `outcome=canceled` and `failure_code=canceled`.

### Uncached verification

Commands, run after sourcing `scripts/lib/go_ssd_env.sh`:

```sh
go test -count=1 ./...
go test -count=1 -race ./...
go test -count=1 -v \
  ./internal/helper/architecture ./internal/broker ./cmd/archcheck
```

Result: PASS for all three commands.

The targeted suite covered strict contract decoding and canonicalization,
negative fixtures, policy weakening, invalid versions and schema bounds,
broker-only connector imports, command/workflow/remote bypasses, duplicate or
unclassified packages, cancellation and recovery, pinned module/workspace
identity, nested modules/workspaces, inactive build-tag bypasses, source changes,
broker capability re-export through aliases, inferred values, generics,
selectors, methods, fields, or nested packages; invalid command arguments; and
failed output sinks.

### Report reproduction

Command:

```sh
scripts/check_go_architecture.sh -format json
```

Result: PASS. Three executions matched
`docs/evidence/CYB-32-architecture-report.json` byte-for-byte at SHA-256
`96aad791524305e54ab815767088c5bd4295dac37f474456eb614a959d3e4530`.

### Documentation and traceability gates

Commands:

```sh
scripts/check_file_sizes.sh
scripts/check_markdown_links.sh \
  docs/design/go-workspace-contract.md \
  docs/design/go-workspace-compatibility.md \
  contracts/architecture/v1/README.md \
  docs/evidence/CYB-32-contract-test-report.md
scripts/verify_prd_trace.sh
scripts/verify_design_decisions.sh
```

Results: PASS.

- File sizes: 141 files checked, zero failures. The only warnings are the
  canonical `outputs/COH-PRD.md` (513 lines) and
  `outputs/COH-Research.md` (740 lines).
- Markdown links: 10 references, zero external lookups, zero failures.
- PRD trace: 187 requirements defined and referenced, exact E01 mappings,
  zero missing or unexpected IDs.
- Design decisions: 10 workflows, 11 boundaries, five tiers, one Mermaid
  architecture diagram, zero ambiguity, and zero failures.

## Acceptance trace

| Acceptance criterion | Current evidence | State |
|---|---|---|
| Named command, domain, policy, workflow, provider, connector, persistence, transport, UI, and helper boundaries; no reverse dependencies | Executable v1 contract and current 15-package graph | Pass |
| Canonical serialization, schema validation, positive/negative examples, versioning, and compatibility | Schema bundle, canonical fixture, strict reader tests, compatibility matrix | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve policy/provenance | Typed tests, deterministic reports, timeout exit `130`, recovery tests | Pass |
| Formatting, vet, unit, race, and architecture checks pass on the exact baseline toolchain | Exact and uncached command results above | Pass locally |
| Refreshed evidence reflects the corrected initial module identity and CYB-33 package additions | Current module, package/file counts, digests, report, and ledger | Pass locally |
| Independent reviewer reproduces and signs the refreshed evidence | Exact report, ledger, unit/race, cancellation, trace, and boundary checks reproduced read-only | Pass |

## Checksum ledger scope

`CYB-32-artifacts.sha256` is generated in bytewise `LC_ALL=C` path order. It
contains, and only contains:

- `LICENSE`, `go.mod`, and `go.work`;
- every `*.go` file below `cmd/` and `internal/` (the same 58-source-file set
  bound by the executable report);
- every file below `contracts/architecture/v1/`;
- `docs/design/go-workspace-contract.md` and
  `docs/design/go-workspace-compatibility.md`;
- this report and `CYB-32-architecture-report.json`; and
- `scripts/check_go_architecture.sh`, `scripts/test_go_contract.sh`, and
  `scripts/lib/go_ssd_env.sh`.

The ledger intentionally excludes itself to avoid a recursive digest.

## Independent review

Independent technical re-review was granted on the final frozen source and
evidence set with no remaining findings. The reviewer independently reproduced
the exact report three times, verified the sorted 85-entry ledger and every
checksum, reran uncached unit and race tests plus cancellation and targeted
boundary tests, and confirmed the type-aware broker guard closes alias,
inference, selector, generic, method, field, structural-capability, nested
package, and symlink bypasses.

Human Product/Security approvals remain E01/M0 governance concerns and are not
an additional CYB-32 leaf acceptance criterion.

## Security, data, compatibility, and documentation impact

- Security: the broker-only connector route and control-plane import boundaries
  remain executable constraints; this evidence does not activate runtime policy.
- Data: the report contains digests, package paths, toolchain/target metadata,
  VCS state, and violation edges, not source content, evidence, credentials, or
  prompts.
- Compatibility: the canonical module is now
  `github.com/ArronJablonowski/COH`. This pre-first-commit correction replaced
  local draft evidence only and was not a deployed or released migration. After
  the first canonical commit, identity changes require the major migration path.
- Documentation: this report and its checksum ledger replace their stale
  local-draft versions.
- Dependencies: the architecture checker remains Go-standard-library-only.

## Remaining completion gates

- Attach or link the reviewed replacement evidence in CYB-32/Linear.
- Record a reviewed Git revision before treating any evidence as release
  evidence.

CYB-33 owns hosted CI orchestration and release-eligibility decisions; this
CYB-32 refresh does not claim either.
