# CYB-7 E03 integration verification report

| Field | Value |
|---|---|
| Issue | COH-E03 / CYB-7 |
| Requirements | FR-010, FR-011, FR-012, FR-013, FR-014, FR-078, FR-079, NFR-009, NFR-011, NFR-012, NFR-020, NFR-021, EVAL-010, EVAL-011, EVAL-015 |
| Verification date | 2026-08-25 |
| Integration checkpoint | `03aecfceb85fd04844927267ec601b7eb3df8e64` |
| Aggregate result | Pass |
| Review status | Local technical evidence complete |

## Outcome

COH-E03's contracts, workstation/server storage, workflow adapter, and
replay/crash behavior now pass one reproducible integration gate. All six child
issues are Done. The clean aggregate run passed the domain and storage
contracts, the same conformance suite against SQLite and PostgreSQL, retained
Temporal history replay, and the frozen 31-task/155-trial fault corpus.

The run recorded zero duplicate confirmed effects and zero false-success
states. It also proved deterministic migration apply, replay, rollback,
checksum denial, and registered mixed-version denial in the common storage
scenario. No unresolved blocking finding remains for E03.

## Parent acceptance audit

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Same domain conformance suite passes against SQLite and PostgreSQL | `storetest.Run` executes the identical five scenarios for both adapters; dedicated race-enabled profile logs passed | Pass |
| Temporal replay and crash injection at every persisted boundary cause no duplicate confirmed side effect | Retained-history replay plus 31 fault tasks × 5 trials; duplicate-confirmed metric = 0 | Pass |
| Schema migration, rollback, and mixed-version rejection are deterministic and documented | Version-keyed adapter registries, shared registered-v2-against-persisted-v1 denial, checksum denial, apply/replay/rollback test, and storage contract documentation | Pass |
| Every child issue is Done | CYB-36, CYB-35, CYB-39, CYB-40, CYB-46, and CYB-44 | Pass |

## Integrated gate inventory

| Gate | Qualified behavior |
|---|---|
| Domain contract | 16 registered kinds, 16 valid payloads, 16 mutation denials, canonical envelope checks |
| Storage contract | Six-method guarded port, typed failures, common conformance, race and architecture checks |
| SQLite profile | Atomic WAL transactions, abrupt-process recovery, outbox replay, digest-verified backups, registered migrations |
| PostgreSQL profile | Atomic transactions, forced RLS, concurrent outbox claims, backup and privileged-role denial, bounded pool |
| Temporal adapter | Five operations, versioned workflow, retained-history replay, identifier-and-hash-only history |
| Replay/crash corpus | 31 tasks, 155 trials, deterministic artifacts, exact locked thresholds, zero duplicate confirmed effects |

## Mixed-version migration rule

SQLite and PostgreSQL now register migrations by `(component, version)` rather
than by component alone. This lets an adapter recognize adjacent registered
artifacts while still comparing the requested plan to the persisted component
identity. If persisted state is v1 and a valid registered v2 plan arrives, the
adapter returns the typed `denied` result before running migration statements.

This is intentionally not an automatic upgrade mechanism. A future schema
transition must define and qualify an explicit transition protocol; binaries
cannot infer, overwrite, upgrade, or downgrade a mismatched persisted version.
The behavior is shared by the reference driver, SQLite, and PostgreSQL and is
documented in `docs/design/storage-port-contract.md`.

## Reproduction and artifacts

Run:

```sh
./scripts/verify_e03_integration.sh
```

The clean run produced `integration-result.json`, one log per component gate,
the complete nested replay-evaluation artifact set, and a relative SHA-256
ledger. The result binds commit
`03aecfceb85fd04844927267ec601b7eb3df8e64`, records a clean worktree, and
reports all E03 criteria as passed.

The integration-result digest is
`sha256:072e814c9710dd8b0a6d0b0a302d67287691e8b8d464abcf6ce6b78943b0b114`.
The aggregate artifact-ledger digest is
`sha256:13ad2286e18bcdd6b3727385b4d642b4b83a934bef20a389d25780b14d655da3`.

## Baseline evidence

The clean report checkpoint `3f0c1c3dc428942752645d9021927d25e87b28f4`
passed all 18 required baseline stages with
`quality_gate_promotable=true`. The quality report digest is
`f4bd11ea374a29bb28af122f97fb2d49ae6475563f164428cd8edb578e05e439`;
its provenance records 319 source files, Go 1.26.7 on darwin/arm64, and
`vcs_modified=false`.

## Residual scope

- Real broker and connector dispatch/reconciliation qualification belongs to
  later epics; E03 establishes and verifies the control-plane contract they
  must implement.
- Production backup catalogs, TLS endpoints, database roles, deployment
  rollout, and disaster restoration remain deployment responsibilities.
- Obtain an independent security architecture review before the first
  production release, as approved by the Product Owner. This is a non-blocking
  follow-up and not an unresolved E03 finding.
