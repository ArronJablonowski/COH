# CYB-46 Temporal WorkflowEngine verification report

| Field | Value |
|---|---|
| Issue | COH-E03-05 / CYB-46 |
| Requirements | FR-011, FR-012, NFR-012, EVAL-015 |
| Verification date | 2026-08-25 |
| Contract | `coh.workflow/v1` |
| Workflow | `coh.operation.v1` |
| Implementation checkpoints | `e786afb`, `f4674a8` |
| Data classification | Operational identifiers and SHA-256 digests |
| Review status | Local technical evidence complete |

## Outcome

The product now has a guarded, replaceable workflow-engine boundary and a
Temporal implementation for versioned operation lifecycles. It starts, signals,
queries, cancels, and replays without exposing Temporal types or arbitrary
history content. Workflow history input and signals contain only identifiers,
registered tokens, and hashes.

## Acceptance evidence

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Start, signal, query, cancel | SDK client mapping and deterministic Temporal test environment | Pass |
| Versioned workflow replay | Registered `coh.operation.v1` plus retained history replayed five times | Pass |
| Narrow interface and no bypass | Five typed operations, guarded results, no policy/executor/connector surface | Pass |
| Typed invalid, denial, conflict, cancellation, timeout | Guard and adapter tests, changed replay denial, backend redaction | Pass |
| Idempotent boundaries | Exact start replay, changed start conflict, exact signal dedupe, changed signal denial | Pass |
| Cancellation and recovery | Reason digest precedes cooperative cancellation; clean-context recovery after canceled/expired calls | Pass |
| History hygiene | Fixture and payload tests contain only scope identifiers, versions, and SHA-256 digests | Pass |
| License and dependency closure | 91 exact modules and license hashes; unlicensed newer graph rejected | Pass |
| Vulnerability gate | Patched `x/net` and `x/text`; locked database reports zero findings | Pass |
| Full baseline | 18 of 18 stages passed at the implementation checkpoint | Pass |

## Relevant traces

The lifecycle trace starts `coh.operation.v1`, delivers an `advance` signal
twice with the same idempotency and request digests, and then completes. The
result sequence is two—not three—proving the exact duplicate did not advance
durable state.

The denial trace reuses one idempotency digest with a changed request digest.
The query snapshot becomes `denied`, retains the first payload digest, and does
not complete. The test then cooperatively cancels the workflow.

The replay trace rehashes the retained JSON history, parses it through the SDK,
registers the exact v1 workflow name, and replays successfully. A byte-changed
fixture is denied during adapter construction before replay.

## Baseline evidence

The implementation baseline passed all 18 stages with report digest
`7322573a1fb4c115c760520411d02d343da16a8d18026130a1bdeca28424bd98`.
It covered 23 architecture packages with zero violations, approved 91 exact
modules and license hashes, and found zero vulnerabilities after patched
transitive pins.

A final clean baseline report and checksum ledger are attached to CYB-46 after
this evidence packet is committed and pushed.

## Residual scope

- Concrete consequential-action workflow definitions remain later M1/M2 work;
  this adapter cannot itself dispatch an action.
- Persistent workstation/server Temporal topology and credentials are packaging
  and deployment-profile work.
- CYB-44 will inject crashes across workflow/action boundaries after CYB-40 and
  this adapter are complete.
- Independent security architecture review remains required before the first
  production release and is non-blocking for this M1 leaf.
