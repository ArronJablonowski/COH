# Native release supply-chain design

Status: implemented for COH-E02-04 / CYB-37; completion remains gated on the
frozen evidence ledger and hosted verification.

Traceability: SEC-033, SEC-034, NFR-025, and EVAL-029.

## Outcome and non-goals

COH produces an independently verifiable native bundle without Docker. The
bundle contains only `archcheck`, `installgate`, `qualitygate`, the Apache-2.0
license, the file-digest inventory, and the bounded lifecycle installer.
Release metadata contains no secrets, source
bytes, user paths, host names, or wall-clock timestamps.

This contract does not claim that a CI fixture signature is a release approval,
that GitHub-hosted and native builders have the same trust base, or that a
shared Docker daemon is an isolation boundary. OCI attestations remain
inapplicable until COH publishes an OCI artifact.

## Build type

The build type URI is `https://coh.invalid/build-types/native-release/v1`. Its
external parameters are the semantic release version, target, repository, and
exact Git revision. Internal parameters contain the CYB-37 requirement set.
Resolved dependencies bind the full source snapshot plus Git commit and the
exact Go compiler binary and canonical release-policy digest. Production
assembly accepts only a policy-pinned compiler digest and invokes that exact
executable for each fixed command build. The archive is the in-toto subject.

The statement uses `_type=https://in-toto.io/Statement/v1` and
`predicateType=https://slsa.dev/provenance/v1`. Those names and the
`buildDefinition`/`runDetails` structure follow the current
[SLSA build-provenance specification](https://slsa.dev/spec/v1.2/build-provenance).
No build level is asserted because SLSA levels depend on controls of the actual
builder, not merely the JSON shape.

The release SBOM uses CycloneDX 1.6 and binds the archive and every packaged
file by SHA-256. License choices use SPDX identifier objects as required by the
[CycloneDX 1.6 JSON schema](https://cyclonedx.org/schema/bom-1.6.schema.json).

## Native Studio builder

This identity covers a local build on the dedicated Mac Studio using the pinned
toolchain and mutable storage below `/Users/aj_lobster/Developer/COH-toolchains`.
The provenance is signed only after the current workspace snapshot, Git
revision, compiler binary, target, archive, SBOM, and checksum records verify.
Production signing always selects this identity; ambient `CI` cannot promote a
native release invocation to the hosted identity. The identity makes no claim
about GitHub-hosted isolation.

## GitHub-hosted builder

This identity covers the pinned `ubuntu-24.04` GitHub Actions workflow with
exact action revisions, a clean checkout, the selected pinned Go lane, and the
fixed repository dispatcher. The CI-fixture signer tests deterministic assembly
and offline verification but is not a publisher identity. A release workflow
must use an approved release signer before publishing a production bundle.

## Offline verification

The verifier needs the bundle, the matching frozen release policy, its pinned
public key, and no network. It performs these checks in order:

1. reject an unknown target, compiler, builder, signer role, or key;
2. require the exact bundle file set and verify the signed outer manifest;
3. verify every recorded length and SHA-256 digest;
4. verify detached signatures for checksums, SBOM, and provenance;
5. recompute the archive checksum and reject unsafe tar/gzip metadata;
6. inspect packaged Go build metadata against the release policy;
7. reproduce the canonical CycloneDX and SLSA statements from the verified
   archive, source, compiler, and build parameters.

Any invalid input, denial, timeout, cancellation, or partial publication fails
closed. A failed build directory has no valid signed manifest and is not a
release. Re-running uses a fresh directory; a competing destination is
preserved rather than overwritten.

## Install, upgrade, rollback, and removal

`scripts/install_release.sh` is a thin dispatcher that requires an explicit
absolute independently trusted `COH_INSTALLGATE_BIN`; it never selects or
executes code from an unverified source or mutable install state. `installgate`
pins the explicit mode-0700 prefix with Go's contained `os.Root` operations. A
new install requires an empty prefix and publishes a private marker, exact
version tree, and bounded state. The archive's signed file inventory is copied
into the version and its digest is bound in current/previous state. Upgrade
verifies the new tree before switching. Rollback re-verifies every prior file
and its inventory before switching. Removal requires the marker, valid state,
verified current version, and exact managed root before contained deletion.
Tests cover repeated-operation denial, regular and symlink corruption,
interrupted-state recovery, upgrade, rollback, unexpected content, and removal.
An fsynced bounded lifecycle journal precedes each mutation; retry reconciles a
partial install or upgrade, recognizes a completed state switch, or finishes a
contained removal without trusting a missing release tree. Journal, state, and
release-directory publications use file and parent-directory sync barriers.
`installgate` handles interrupt/termination signals and a bounded deadline
(`COH_INSTALL_TIMEOUT`, default ten minutes); copy, hashing, traversal, and
fixed-entry removal preserve typed cancellation or timeout failures.

Bootstrap order is normative: first verify the detached signatures, manifest,
archive, SBOM, and provenance with an independently trusted `releasegate` built
from the reviewed pinned source revision. Next extract the already verified
archive into a private directory and check every entry against its embedded
`share/coh/release-files.sha256`. Only then set `COH_INSTALLGATE_BIN` to that
verified extracted `bin/installgate` and invoke the wrapper. The packaged gate
must never authenticate itself or execute directly from an unverified source.
The public policy pins the release compiler and signer; the private signing key
is not needed for offline verification or installation.

## Key and compatibility lifecycle

The repository contains only approved public keys. Production private keys live
outside the checkout, are never model-visible, and must be supplied by an
authorized release operator. Rotation adds a new public key before use, retains
the prior key through the rollback/support window, and records both policy
digests. Revocation stops new signing immediately but preserves the historical
verification material and records the affected release range.

The v1 reader is strict. Contract or canonicalization changes require a version
bump, old/new fixtures, upgrade verification, rollback verification, and an
updated offline verifier. Historical CYB-32/CYB-33 evidence remains unchanged.
