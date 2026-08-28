# CYB-184 transactional extension-lifecycle verification report

| Field | Value |
|---|---|
| Issue | COH-E25-03 / CYB-184 |
| Requirements | FR-014, FR-015, FR-042, FR-043, SEC-018, SEC-020 |
| Verification date | 2026-08-28 |
| Verified checkpoint | `49267d6c44c0f7a51659b0939e3e0bfa81cc9a62` |
| Aggregate result | Pass |

## Outcome

COH now admits, activates, deactivates, upgrades, and independently authorized
rolls back reviewed signed data-plane extensions through one transactional,
scope-exact lifecycle. The implementation binds every operation to the active
profile and capability graph, current trust and revocation state, narrowed
permissions and scope, audit availability, and fresh broker-observed E-stop
state.

Activation publishes nothing until every ordered registration succeeds. A
failure or cancellation records an unwind and revokes completed effects in
strict reverse order. Deactivation blocks new work, proves drain or bounded
cancellation, revokes only the owner's registrations, commits terminal audit,
and atomically removes the active pointer. Durable SQLite records, rather than
process memory, drive exact restart recovery.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Activation validates signature, promotion, qualification, policy, permissions, active profile, dependency graph, audit, and E-stop before the first effect | Signed manifest and intent contracts, command-root admission, `TestAdmissionIsCanonicalImmutableAndCurrent`, and authority-drift denials | Pass |
| Partial activation, failure, cancellation, and timeout never publish partial state and unwind in exact reverse order | Sealed phase controller, durable receipts and handles, activation/context tests, and lost-response replay tests | Pass |
| Deactivation drains or boundedly cancels owned work, audits terminal outcomes, and removes only the owner's effects | Scoped deactivation controller and success, false-drain, failed-revocation, and active-pointer tests | Pass |
| Restart and retry resume from sealed durable state without duplicate effects or in-memory authority | SQLite CAS store, independent process-exit recovery, committed lost-response recovery, and canonical durable-record enforcement | Pass |
| Concurrent exact operations converge; conflicting operations, stale revisions, tamper, and changed replay fail closed | Concurrent activation and activation/deactivation tests, durable tamper test, lineage tests, and strict decoders | Pass |
| Upgrade and rollback preserve inactive predecessor lineage, and rollback requires current independent authorization | Revisions 1-to-2-to-3 lifecycle test, independently signed rollback decision, and stale-revision denials | Pass |
| Agents and extensions cannot acquire lifecycle, broker, policy, approval, audit, credential, E-stop, runner, connector, or validator authority | Data-only schemas, non-serializable authority/E-stop observations, command/broker boundary tests, and `ARCH-005` | Pass |

## Admission and control boundary

The immutable manifest carries only data-plane declarations and three distinct
signature roles: publisher, independent reviewer, and owner. Verification uses
current command-root authority snapshots; identities embedded in a document do
not grant their own authority. Unknown members, noncanonical encodings,
duplicate logical identities, stale revisions, signature drift, revoked keys,
scope or permission widening, missing dependencies, and model or agent actors
deny before any effect.

The native command root is the only production lifecycle entry point. It binds
fresh authenticated administrator authority, then reads current E-stop state
through a broker-owned control port immediately before execution. These values
cannot be serialized. Architecture rule `ARCH-005` prevents workflow, agent,
provider, connector, transport, policy, UI, and helper packages from importing
the lifecycle engine; production agents can resolve already-active
capabilities, but cannot install, activate, deactivate, promote, review, sign,
roll back, or revoke extensions.

## Transaction, recovery, and lineage proof

Activation persists `prepared` before the first effect. Each successful stage
returns a receipt and data-only revocation handle bound to the exact extension,
manifest, transition, registration, scope, registry revision, generation, and
owner. Publication is atomic after all stages. Failure changes the durable phase
to `unwinding`, and recovery advances only after proving each reverse-ordered
revocation.

Deactivation prevents new admission, then processes owned work and registration
effects without touching another extension or any control-plane service. The
SQLite store uses revision-checked atomic updates for transitions, receipts,
active pointers, and lifecycle lineage. Tests terminate a separate writer
process after committed writes, reopen SQLite, reconstruct the operation, and
complete without duplicate effects.

Upgrade and rollback tests establish durable inactive revisions 1, 2, and 3.
Normal upgrades require the current active predecessor and monotonic lineage.
Rollback to revision 1 succeeds only after re-verification and a current,
scope-exact independent rollback decision; historical success is never reused
as present authority.

## Focused verification

`scripts/verify_extension_lifecycle.sh` passed from the clean verified
checkpoint. It validates all schemas, reserved-field and canonical-record
constraints, focused tests, 20 repeated runs, race, vet, static analysis,
architecture, worktree secrets, licenses, size, links, registered fuzz seeds,
and diff hygiene.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/extension-lifecycle.Ddhj27/extension-lifecycle.log
SHA-256 03a7e263d8a2fea53698916abe48873cddac250d0c2ac10a0bf6157746dcd42c
```

The focused architecture gate examined 118 packages with zero violations. The
license inventory covered 183 Go modules, two module notices, and two shipped
inputs with zero denials. The secret scan covered approximately 12.22 MB and
found no leaks. All 14 registered fuzz targets executed their seed callbacks.
Separate live fuzz sessions exercised approximately 759,710 lifecycle
transition inputs and 1,152,760 lifecycle document inputs without a failure.

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`: format, file size,
workflow policy, worktree and history secrets, architecture, quality contract,
vet, static analysis, unit, race, fuzz seeds, license, dependencies, SBOM,
supply chain, evidence secrets, and provenance.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.futMyg/quality-report.json
```

Embedded report digest:
`295d61e76fa6a39516da34900acfe6097166ff9e69a1ac6e7960c16a6c496068`.
Report-file SHA-256:
`4278241d2c5766516917ab966ea6694abd001f8f98966eb58d25729088943266`.
Provenance records 2,207 source files, source digest
`505d7aad1162ec3d82ca1820da3bdf7a8aba8e28cb07fff4eb14edd3f94bfff8`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_extension_lifecycle.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- CYB-185 owns the signed, versioned extension catalog and discovery layer that
  consumes this lifecycle without gaining activation authority.
- Deployment packaging and local Ollama model integration remain subsequent
  leaves; they must preserve this lifecycle, active-profile, and capability
  graph boundary.
- Independent security architecture review remains required before the first
  production release under the approved COH-E01 follow-up.
