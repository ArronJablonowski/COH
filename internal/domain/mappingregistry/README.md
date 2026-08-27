# Mapping registry domain

This package implements CYB-81 / COH-E11-03 for FR-021 and FR-025. It accepts
only strict data records from the [mapping contract](../../../contracts/mapping/v1/README.md),
selects an exact signed source mapping, and emits a newly validated CYB-80
envelope. It does not read raw evidence or invoke policy, connectors, tools,
models, networks, filesystems, shells, or executors.

## Compatibility and migration

V1 is pinned to the CYB-80 target manifest, OCSF 1.9.0, and ECS 9.5.0. A new
source schema, target pin, operation, scalar type, role, or coverage rule needs
a new signed manifest revision and complete corpus replay. A successor names
the exact predecessor digest and increments the manifest revision by one.
Historical manifests, outcomes, envelopes, receipts, audit, and provenance are
immutable and remain readable after promotion.

## Signing and key rotation

The package passes a domain-separated manifest digest, publisher, public key
ID and revision, validity interval, purpose, and revocation identity to the
signature verifier. No key material crosses the port. Rotation publishes a new
trusted public-key revision and signs a new manifest envelope; it never
rewrites an existing signature. Keep the retired verification key available
for historical verification until retention ends. Revoke a compromised key
through the verifier's monotonic revocation state, then register and promote a
new manifest only after independent review and corpus replay.

## Recovery and rollback

An idempotency key binds the canonical command digest. Exact replay returns the
stored receipt; changed replay is durably denied. An incomplete begin resumes
from stored identities, and a lost commit response is recovered from the
atomic receipt/outcome pair. Cancellation and timeout use a short independent
context to persist a terminal record without publishing an envelope.

Promotion is optimistic and monotonic. Rollback may select only the immediate
verified predecessor and creates a new registry revision; it never changes a
manifest or prior result. Registry or signature revocation blocks subsequent
application. Operators should stop promotion, inspect the signed predecessor
and current revocation state, issue a rollback with the exact expected
registry revision, and replay the vendor corpus before reopening promotion.

## Privacy and extension boundary

Original fields, source identity, mapping tables, unmapped paths, and entity
hints inherit case scope and classification. Persisted records and traces use
digests and closed reason codes; they do not log vendor values, signature
bytes, or key material. V1 extensions are data-only: new executable expression
engines, wildcard paths, callbacks, direct I/O, and broader authority require a
new reviewed contract and cannot be injected into this package.

Run `scripts/verify_normalization_mapping_registry.sh` from the repository root
for the focused unit, vendor, repeat, race, vet, static-analysis, architecture,
file-size, link, and checksummed-evidence gates.
