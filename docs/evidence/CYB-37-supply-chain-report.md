# CYB-37 supply-chain verification report

| Field | Value |
|---|---|
| Issue | COH-E02-04 / CYB-37 |
| Requirements | SEC-033, SEC-034, NFR-025, EVAL-029 |
| Contract | `coh.release-policy/v1`, contract v1.0.0 |
| Baseline | Go 1.26.7, required |
| Qualification | Go 1.27.0, required-to-pass and non-promoting |
| Mutable root | `/Users/aj_lobster/Developer/COH-toolchains` |
| Docker dependency | None |

## Outcome and evidence model

The native release gate builds its fixed commands with the selected pinned Go
executable, creates a canonical archive, CycloneDX 1.6 SBOM, checksum, and SLSA
v1 provenance, then signs the metadata and exact outer manifest. Production and
public CI-fixture signer roles are cryptographically distinct. Production
provenance binds the canonical policy, source snapshot, Git revision, approved
compiler binary, target, archive, SBOM, and checksums.

Final machine reports and the production-signed sample live outside the Git
tree under the internal toolchain artifact root and are attached to Linear with
their exact SHA-256 digests. This repository report and `CYB-37-artifacts.sha256`
freeze the portable public inputs without creating a self-referential source
digest. Earlier dirty-tree reports remain diagnostic checkpoints only.

## Acceptance and adversarial coverage

| Area | Automated and retained proof |
|---|---|
| Closed inputs and licenses | Exact v1 builders, targets, Go versions/digests, archive entries, package identities, signer roles, Apache-2.0 inventory, and forbidden-license denial contract |
| Determinism | Two independent builds require identical names and bytes; gzip/tar headers, PAX records, ordering, modes, timestamps, and trailing streams are canonical |
| Signed artifacts | Release-role Ed25519 signatures bind checksum, CycloneDX SBOM, SLSA provenance, and outer self-digested manifest |
| Policy and provenance | Canonical release-policy, source, revision, compiler, builder, target, and archive digests are cross-bound and re-derived during verification |
| Binary identity | Packaged command path, Go version, GOOS/GOARCH, CGO state, and absent VCS metadata are verified from the downloaded archive |
| Denial and malformed inputs | Wrong role/key, policy subset/traversal/unknown fields, archive tamper/extra/symlink/trailing stream, SBOM/provenance drift, and output collision deny |
| Timeout and cancellation | Release assembly/verification and lifecycle expose typed deadline/signal cancellation; mid-copy cancellation preserves the journal and retry recovers |
| Lifecycle | Trusted bootstrap, contained `os.Root` operations, exact file inventory, install/verify/upgrade/rollback/removal, corruption/symlink denial, fsync barriers, and pre/post-state crash recovery |
| Independent review | Read-only review resolved bootstrap, TOCTOU, rollback, toolchain, builder, policy, archive, recovery, durability, cancellation, and file-size findings; final review approved |

## Verification commands

```sh
export COH_NATIVE_STORAGE_ROOT=/Users/aj_lobster/Developer
export COH_TOOLCHAIN_ROOT=/Users/aj_lobster/Developer/COH-toolchains

# Focused package and lifecycle proof, repeated with each pinned Go root.
go vet ./internal/helper/supplychain ./cmd/installgate ./cmd/releasegate
go test -count=1 ./internal/helper/supplychain ./cmd/installgate ./cmd/releasegate
go test -count=1 -race ./internal/helper/supplychain ./cmd/installgate ./cmd/releasegate
scripts/check_supply_chain.sh
scripts/test_release_lifecycle.sh

# Complete offline lanes on the same frozen source tree.
COH_CI_OFFLINE=true scripts/run_ci_quality.sh baseline
COH_CI_OFFLINE=true scripts/run_ci_quality.sh go1.27
```

## Compatibility, migration, and limitations

The v1 reader rejects unknown fields and any change to its exact compiled
builder, target, compiler, archive, signer, or canonicalization sets. Such a
change requires a new contract version, old/new fixtures, and explicit upgrade
and rollback evidence. Historical CYB-32, CYB-33, and CYB-38 evidence is not
rewritten or represented as current.

Installation requires an independently trusted `releasegate` to verify the
bundle, private extraction checked against `release-files.sha256`, and an
explicit absolute `COH_INSTALLGATE_BIN` pointing to that verified extracted
gate. Production private signing material remains outside the repository and
logs. Docker and an external drive are not required.

This issue contains no model invocation path, so it cannot truthfully exercise
Ollama, local models, or Codex inference. Those end-to-end provider checks are
required at the first subsequent issue that invokes model providers; no model
coverage is claimed by this supply-chain evidence.
