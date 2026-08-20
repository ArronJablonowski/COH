# COH release supply-chain contract v1

Status: implemented for COH-E02-04 / CYB-37; completion remains gated on the
frozen evidence ledger and hosted verification.

Traceability: SEC-033, SEC-034, NFR-025, and EVAL-029.

## Boundary

The v1 contract accepts only the exact compiled release policy, fixed native
targets, three known Go command packages, the repository license, file-digest
inventory, lifecycle installer, and
an approved Ed25519 signer role. It emits a deterministic gzip/tar archive, a
CycloneDX 1.6 SBOM, an in-toto Statement v1 carrying the SLSA provenance v1
predicate, a checksum document, detached signatures, and a self-digested outer
manifest. The verifier rejects missing, extra, malformed, reordered, symlinked,
oversized, changed, or incorrectly signed inputs.

Signed provenance binds the canonical policy digest. Release-role assembly
accepts only a policy-pinned Go executable digest and invokes that exact
executable itself for every packaged command build; caller-prebuilt binaries
are not accepted.

The normative policy schema is
[`release-policy.schema.json`](release-policy.schema.json). The executable
policy is [`../../../ci/release-policy.json`](../../../ci/release-policy.json).

## Signature roles

- `release` identifies an approved release publisher. Production publication
  must use the separately provisioned private key held outside the repository
  and the policy-pinned `release-ed25519.pem` public key. The private key must
  never be copied into a bundle, repository file, diagnostic, or CI fixture.
- `ci-fixture` is a public deterministic test identity. Its private seed is
  intentionally derivable, so it proves signature mechanics and
  reproducibility only. It can never authorize a production release.

Signatures use Ed25519 over a domain-separated canonical record that binds the
role, key identifier, issue, requirements, subject name, SHA-256 digest, and
length. The manifest and each checksum, SBOM, and provenance document are
signed. The signed checksum binds the native archive.

## Reproducibility and binary identity

Archive entries are ordered, regular files only, use fixed modes and zero tar
timestamps, and are compressed without host names or timestamps. Packaged Go
binaries must report the exact command package, pinned Go version, target
GOOS/GOARCH, `CGO_ENABLED=0`, and no embedded VCS time/revision/dirty settings.
The gate builds twice and requires byte-identical file sets and contents.

The contract makes no SLSA build-level claim. The signed provenance is
format-compatible and records the actual builder identity, external parameters,
source snapshot and Git revision, and pinned compiler binary. Higher SLSA
levels require build-platform controls outside this repository.

The signed archive contains the release file-digest inventory and `installgate`.
Lifecycle operations must be launched by an independently trusted gate (the
thin wrapper requires an explicit absolute `COH_INSTALLGATE_BIN`) and use
contained `os.Root` filesystem operations. Installed state binds current and
previous inventory digests; rollback verifies the entire prior tree before the
state switch.

Obtain that bootstrap only after a trusted `releasegate` verifies the bundle's
release-role signatures and exact policy. Extract the verified archive into a
private directory, check the extracted files against the signed archive's
`share/coh/release-files.sha256`, and set `COH_INSTALLGATE_BIN` to the verified
`bin/installgate`. Never point the variable at an unverified source tree or an
executable selected from mutable install state.

## Compatibility

Readers reject unknown fields and unsupported versions. A field addition,
algorithm change, signature-domain change, archive path change, or canonical
encoding, approved key, target, or archive-set change requires a new contract
version. Key rotation requires an overlap contract and rollback evidence;
previously signed artifacts remain verifiable with the historical policy
retained in their release evidence.
