# Evidence-linked entity resolution design freeze

Status: frozen for implementation
Stable key: COH-E11-04
Linear: CYB-83
Requirement: FR-025
Depends on: COH-E10, COH-E11-01 / CYB-80, COH-E11-03 / CYB-81

## Purpose and boundary

The entity resolver turns verified CYB-81 typed identifier hints into
case-local observations and evidence-backed entity candidates. It records why
observations may or may not refer to the same entity, bounded confidence,
counterevidence, and append-only merge and split history. Every result is
reproducible from exact versioned inputs and transformations.

FR-025 requires tenant-scoped, evidence-backed, reversible, confidence-labeled
resolution and correlation. V1 deliberately narrows automatic entity
resolution further to one exact organization, tenant, and case. It never
searches or joins another case. A future cross-case workflow requires a new
reviewed contract, explicit authority, privacy analysis, and separate audit;
tenant equality alone does not authorize linkage.

This package does not extract identifiers from evidence, read event bytes,
correlate events, create hypotheses, modify evidence, or authorize access.
CYB-86 consumes entity identities and history but cannot rewrite them. Raw and
normalized events remain authoritative; an entity is an analytical projection.

## Frozen dependency bindings

| Dependency | Exact retained binding | Entity-resolution rule |
|---|---|---|
| COH-E10 | organization, tenant, case, raw artifact, raw manifest, ingest receipt, source provenance, classification | Verify the complete immutable evidence identity without receiving evidence bytes or storage locations. |
| CYB-80 | validated envelope ID and digest, case, source identity, classification, lineage, mapping set, transformation | Accept only a validated exact envelope binding; entity state cannot weaken classification or mutate the envelope. |
| CYB-81 | mapping manifest digest and revision, rule ID, output path, role, identifier type, normalization method, confidence ceiling, source-field digest | Accept only a hint emitted by the exact applied mapping outcome; a hint proposes an observation and grants no merge authority. |
| Case lifecycle | current organization, tenant, case identity and classification | Reject closed, deleted, mismatched, unavailable, or less restrictive case state according to the narrow verifier decision. |
| CYB-86 | immutable entity/candidate/decision/history digests | Downstream projections consume references only and must reproduce against the same entity-resolution method version. |

Every binding is required for success. Artifact digest alone, envelope ID
alone, an unbound identifier, or a caller assertion is insufficient.

## Scope and privacy identity

An entity namespace is the exact tuple `(organization_id, tenant_id, case_id)`.
Commands, observations, candidates, entity records, decisions, receipts,
audit, and provenance all carry or are digest-bound to that tuple. Stores use
the complete tuple as a mandatory partition key. A returned record is
revalidated against the requested scope before use.

The entity domain never receives a raw username, hostname, IP address, process
ID, file hash, cloud resource ID, or other identifier value. A trusted
case-scoped derivation boundary produces an opaque match digest:

`HMAC-SHA-256(case_match_key, "COH-ENTITY-MATCH-V1\x00" || identifier_type || "\x00" || canonical_identifier)`

The observation binds the digest, derivation key revision, CYB-81
normalization method, identifier type, and role. The key is unique per case,
non-exportable, and never crosses the port. Thus equal values in two cases do
not produce linkable digests, and low-entropy identifiers cannot be tested
with an unkeyed dictionary. A verifier confirms the digest against the bound
envelope and hint without returning the value or key.

Key rotation is append-only. Existing observations retain their key revision.
A reindex operation emits a new verified observation and an explicit alias
proof; it never edits an old digest. Lookup compares equal type and digest only
within one key revision unless a verified alias proof bridges revisions.

## Typed observation

A canonical observation binds:

- schema/contract and resolution-method versions;
- organization, tenant, case, observation, and operation identities;
- identifier role, identifier type, normalization method, opaque case match
  digest, and derivation-key revision;
- CYB-81 confidence ceiling and exact mapping manifest/rule/output/source-field
  identities;
- CYB-80 envelope, transformation, source identity, and classification;
- COH-E10 artifact, manifest, ingest receipt, and source provenance digests;
- observation time, validity state, and canonical observation digest; and
- audit and provenance linkage.

The v1 roles and types are the closed CYB-81 catalog: host name, user name,
network IP, process ID, file SHA-256, and cloud resource ID with their exact
allowed identifier types and normalization methods. A role/type/method drift,
unknown enum, raw value, empty binding, digest substitution, or classification
downgrade is denied.

Observations are immutable. Rejection, expiry, reindexing, correction, and
supersession create new records that reference prior digests. They never erase
the evidence-backed assertion that was received.

## Candidate lookup and ambiguity

Candidate lookup uses only the complete case scope plus exact identifier type,
case match digest, and compatible derivation revision. Role is evidence about
usage, not a license to equate different identifier types. There are no
wildcards, fuzzy strings, edit distance, regular expressions, embeddings,
model guesses, fallback normalization, or cross-case indexes.

An exact identifier match is evidence for a candidate, not proof of identity.
Shared accounts, NAT addresses, recycled hostnames, reused process IDs, and
cloud identifiers may legitimately refer to multiple entities. Therefore:

- zero active matches creates an unresolved candidate, not a fabricated merge;
- one active match proposes that entity with recorded confidence components;
- multiple active matches returns an explicit ambiguous candidate; and
- type, scope, key-revision, classification, or provenance mismatch denies the
  lookup rather than broadening it.

Candidate ordering is canonical by entity ID and observation digest. Store
iteration order never affects a decision.

## Confidence and counterevidence

Confidence is an integer from 0 through 1,000,000 millionths with a closed
method name and version. Floating point is forbidden. Every output records the
ordered signed integer components, supporting observation digests,
counterevidence digests, method version, pre-ceiling total, applicable CYB-81
ceilings, final score, and label.

The labels are deterministic:

| Score | Label |
|---:|---|
| 0–249,999 | very_low |
| 250,000–499,999 | low |
| 500,000–749,999 | medium |
| 750,000–899,999 | high |
| 900,000–1,000,000 | very_high |

The frozen `coh.entity-confidence` v1 method assigns 500,000 for an exact
typed match, 150,000 for each additional independent corroboration (at most
two), the maximum declared source-quality weight (0/25,000/50,000/100,000),
and the maximum declared recency weight (0/50,000/100,000). Multiple active
entity matches subtract 250,000. Counterevidence has fixed reason-specific
weights from -150,000 through -1,000,000; temporal impossibility, explicit
separation, and analyst rejection also block merge. The canonical executable
method fixture is `contracts/entity/v1/fixtures/confidence-method-v1.json`.

The final score cannot exceed the lowest confidence ceiling among observations
used by the decision. Repeated observations from the same source/provenance
family do not count as independent corroboration. Missing evidence does not
become negative evidence, and the absence of counterevidence does not increase
confidence.

Counterevidence is first-class and immutable. V1 closed reasons include shared
identifier, conflicting attribute, temporal impossibility, explicit
separation, source unreliability, stale observation, and analyst rejection.
Each item binds its supporting evidence identities and may reduce confidence,
force ambiguity, or prohibit a merge. It cannot be omitted from a decision
because it is inconvenient. The exact component weights and blocking rules are
frozen with the v1 method fixture before implementation in Task 6.

No confidence threshold automatically authorizes a merge. Confidence informs
a deterministic proposal; merge and split remain explicit, scoped, audited
state transitions under a current narrow authorization decision.

## Entity, merge, and split state

An entity record has a stable case-local ID, revision, status, classification,
sorted member observation digests, sorted alias proofs, current confidence
summary, creation decision, latest history digest, audit digest, and provenance
head. Classification is the most restrictive classification of its members and
can never be reduced by entity resolution.

`EntityRef.record_digest` is the SHA-256 digest of the canonical immutable
entity-revision core: versions, entity ID/revision, scope, status,
classification, members, alias proofs, confidence, and created/updated times.
The decision, history, audit, and provenance digests are excluded from that
core and then bound onto the full entity record. This staged definition avoids
a cryptographic cycle (decisions and histories themselves contain entity
references) while still making every referenced state field immutable and
verifiable. The full stored entity remains bound by its audit and provenance
records.

Merge requires exact current revisions for at least two active entities, an
explicit ordered supporting set, the complete known counterevidence set, a
closed reason, current scope authorization, and a deterministic resulting
member set. It creates a new entity, marks inputs superseded, and appends one
atomic history event. It does not overwrite or delete input entities.

Split names one active entity revision, partitions every current member exactly
once into at least two non-empty new entities, identifies the merge/history
event being reversed or corrected, carries evidence and counterevidence, and
appends one atomic history event. It marks the input superseded and creates new
entities. Split never resurrects a prior record silently and never changes an
observation.

Concurrent mutation uses optimistic revisions. Stale, incomplete, overlapping,
duplicate, missing-member, cyclic-alias, or cross-case transitions fail closed.
History is a digest-linked directed acyclic graph and is validated before a
record is released.

## Authority boundary

Observation and resolution are read/derive operations after evidence and case
verification. Merge, split, reject, and reindex are analytical mutations. They
require a current narrow authorization-decision verifier bound to actor ID and
revision, exact case, operation, input revisions, canonical command digest,
decision digest, expiry, and revocation state. The entity package receives no
policy source, role catalog, token, credential, approval secret, or grant that
can be widened. A model, hint, score, or entity candidate is never authority.

The package invokes no connector, provider, tool, executor, network, filesystem,
shell, SQL client, or generic callback. Authorization failure, unavailability,
expiry, revocation, or mismatch denies the mutation before state change.

## Failure matrix

| Concern | Closed failure |
|---|---|
| Canonical record, schema, enum, bound, or digest invalid | `invalid_input` with a closed validation reason |
| Organization, tenant, case, envelope, evidence, mapping, rule, or hint mismatch | `evidence_binding_mismatch` |
| Cross-case lookup or returned record | `scope_mismatch` |
| Identifier type/method/key revision incompatible | `identifier_incompatible` |
| Match set has multiple active entities | `candidate_ambiguous` |
| Confidence components, ceiling, ordering, or arithmetic invalid | `confidence_invalid` |
| Required counterevidence omitted or blocking | `counterevidence_blocked` |
| Merge or split membership/history invalid | `transition_invalid` |
| Expected entity/store revision stale | `revision_conflict` |
| Authorization missing, denied, expired, revoked, or mismatched | `authorization_denied` |
| Idempotency key reused for changed command | `idempotency_conflict` |
| Caller canceled | `context_canceled` |
| Deadline elapsed | `context_deadline` |
| Evidence, authority, store, audit, provenance, key, or clock unavailable | `dependency_unavailable` |

No failure returns a usable new entity, merge/split result, or elevated
confidence. Error and trace records contain scope-safe identities, revisions,
digests, enums, and bounds only—not raw identifiers or evidence values.

## Durable workflow and recovery

1. Strictly decode and canonicalize the command; bind its idempotency key to
   the canonical command digest.
2. Verify exact current case, evidence, CYB-80 envelope, and CYB-81 hint
   identities without receiving source values.
3. Verify the opaque case match digest and derivation-key revision.
4. Load exact case-local observations and entity revisions; revalidate every
   returned record and provenance link.
5. Produce the deterministic candidate and complete confidence/counterevidence
   calculation, or validate an explicit merge/split partition.
6. Verify current narrow authority for mutations.
7. Atomically persist command, observations, candidate/decision, entity changes,
   history, outcome, receipt, audit, and provenance.

An exact replay returns the stored receipt and outcome without recomputation or
duplicate mutation. Changed replay is durably denied. A stale begun operation
resumes from exact stored identities after restart. A lost commit response is
recovered by loading and validating the atomic receipt/outcome. Cancellation or
timeout stops work and records only a terminal outcome through a short
independent persistence context. An indeterminate commit never triggers a
blind second merge or split.

## Migration, rollback, and extension freeze

The initial contract and method are version 1.0.0. New identifier types,
normalization methods, confidence components/weights, counterevidence reasons,
state transitions, cross-case behavior, or key-derivation algorithms require a
new compatibility decision, migrations, and complete corpus replay. Historical
readers and method versions remain available for verification.

Rollback disables new mutations and restores the previous application version;
it does not delete entity history or reinterpret an old score. Analytical
correction uses an explicit split or new decision under the original method.
Schema/data migration is checksum-verified, resumable, backup-aware, and tested
for upgrade and rollback before promotion.

Extensions cannot add executable behavior, raw identifier surfaces, fuzzy or
model matching, cross-case lookup, or broader authority to v1. Such behavior
requires a separate reviewed boundary and cannot silently reuse a v1 receipt.
