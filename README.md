# Cyber Operations Harness

Cyber Operations Harness (COH) is an Apache-2.0 cybersecurity agent harness for evidence-grounded investigation, incident response, threat hunting, detection engineering, vulnerability operations, and analyst reporting.

COH is native-first on macOS and Linux. Docker Desktop and Docker Compose are supported deployment options, not runtime dependencies. The architecture also supports connected and completely air-gapped operation.

## Status

COH is in design freeze and early implementation. The model is an untrusted planner; deterministic policy, approval, credential, execution, evidence, and audit services remain the authority boundary.

The implementation backlog and acceptance gates live in the [COH Linear project](https://linear.app/cyber-operations-harness/project/coh-cyber-operations-harness-2e12a30674e7).

## Canonical documents

- [Research dossier](outputs/COH-Research.md)
- [Product Requirements Document](outputs/COH-PRD.md)
- [Linear backlog mirror](outputs/COH-Linear-Backlog.md)
- [Design decisions](docs/design/)
- [Architecture decision records](docs/adr/)
- [Security governance](docs/security/)
- [CI quality contract](docs/design/ci-quality-contract.md)
- [CYB-33 quality-gate evidence](docs/evidence/CYB-33-quality-gate-report.md)

## Safety contract

- The model cannot authorize or directly dispatch tools.
- Unknown or ambiguous actions fail closed.
- Tenant, case, actor, and organization identity are authorization boundaries.
- Raw evidence is immutable and remains distinct from hypotheses, memory, and summaries.
- Production skill changes require review, testing, signing, promotion, and rollback.
- T4 production validation requires two distinct human approvers and a dedicated isolated runner; it is unavailable in solo mode.

## Engineering constraints

- Handwritten production files fail above 800 physical lines and warn above 500.
- Operational, build, and migration scripts normally remain at or below 300 lines.
- Commands stay thin; domain, policy, workflow, provider, connector, persistence, and transport responsibilities remain separate.
- Native and optional container deployments must pass the same API, workflow, policy, and artifact conformance suites.

See the [PRD](outputs/COH-PRD.md) for the complete product contract.
