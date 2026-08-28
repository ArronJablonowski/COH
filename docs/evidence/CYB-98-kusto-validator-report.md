# CYB-98 Kusto.Language validator conformance report

| Field | Value |
|---|---|
| Issue | COH-E14-05 / CYB-98 |
| Requirements | FR-052, SEC-019 |
| Validator | `kusto-language-12.4.1-coh-1.0.0` |
| Implementation commits | `909f61a` through `6821cd8` |
| Focused verification | `scripts/verify_kusto_validator_evidence.sh` |
| Clean baseline report | `sha256:3af9301a6bc9e762fc4cd6c23c63563a292c61b84137f841c127bfedd8742243` |
| Residual production condition | Independent security architecture review before first production release |

## Delivered boundary

COH now has a pinned, credentialless Kusto.Language helper for the Sentinel
validation leaf. It receives one closed chunked request containing only KQL,
qualified workspace metadata, semantic policy, limits, deadline, and expected
helper identity. It has no actor, authorization, credential, endpoint,
executable, path, environment, generic command, or network surface.

The helper builds an exact `GlobalState` from qualified schema, calls
`KustoCode.ParseAndAnalyze`, rejects all diagnostics and every construct,
operator, function, aggregate, or source outside the frozen registry, and
constructs a terminal literal `take` through Kusto.Language AST nodes. It
formats, reparses, and rebinds the second tree and proves non-terminal structure,
semantic inventory, output schema, and admitted limit before canonical KQL can
leave the process.

The Go service validates current capability, schema, deadline, helper
attestation, signature/qualification, actor/scope authority, policy, audit
reservation, revocation, and E-stop state before launch and repeats current
admission after the helper returns. It verifies every response binding and
commits a redacted audit record before releasing canonical KQL. Exact replay is
reauthorized and revalidated; changed reuse, stale state, revocation, tamper,
timeout, cancellation, helper outage, and audit outage fail closed.

## Compatibility and artifact qualification

| RID | Artifact digest | Package-closure digest | Outcome |
|---|---|---|---|
| `osx-arm64` | `sha256:ed34dea026780204a5e1efd25d93152dfc8d9287a82590fb0b24611f6b01e35d` | `sha256:15f79c443797a3e3ea741765bd90c7b854dae0b077d917e1ec30bbabb63dd9d5` | Reproducible; live conformance passed |
| `linux-x64` | `sha256:760a97a9393ebc5dcbd77f7a33eaf832d4b6479999a75785b9c5c8a4b20bad98` | `sha256:0ee1949105aa48d9d86d01adf81b82fb9a4c361c306db515d897665169181c38` | Reproducible cross-build passed |
| `linux-arm64` | `sha256:f9993d0a107bbbe37b6a5fdb50d6946b2b06403dd983e571920a9b9da0e3f720` | `sha256:dcd923cff3a073b3fe5ea34f9eb0a522e2ee6be54b116e56365f6d413532a520` | Reproducible cross-build passed |

Compatibility is closed to .NET SDK 10.0.400, runtime 10.0.11,
Microsoft.Azure.Kusto.Language 12.4.1, the exact semantic registry and schema
contracts, and the three listed RIDs. Any dependency, runtime, formatter,
registry, AST behavior, or artifact change requires a new identity and full
qualification. Windows remains Docker-only best effort and is not a Tier 1
native helper target.

## Adversarial, policy, audit, and revocation evidence

The deterministic suites execute eight accepted KQL cases, twenty semantic
denials linked from the 38-case denial corpus, and eight hostile metadata
mutations. They additionally cover strict/duplicate/trailing JSON, Unicode,
query/schema/helper/registry/limit substitution, AST and response tamper,
signature/runtime/package drift, stale schema, revocation before and after the
helper, resource truncation, timeout, cancellation, outage recovery, audit
failure, retained-result tamper, exact/changed replay, audit redaction, and
eight-way concurrency. The focused Go suite passed twenty consecutive runs.

The public policy-decision, audit-proof, and revocation fixtures bind query,
actor, scope, request/response, capability, schema, registry, helper,
qualification, policy, reservation, time, and revocation evidence by digest.
Audit contains no KQL, literals, table/column names, workspace identity,
credential, executable path, or stderr.

## Qualification gates

The clean baseline quality run at revision `6821cd8` was promotable and passed
format, file-size, workflow, current/history/evidence secrets, architecture,
quality contract, vet, static analysis, full unit and race, fuzz seeds, license,
dependency allowlist, locked vulnerability database and govulncheck, SBOM,
supply-chain reproducibility, and provenance. The native executor suite also
proved macOS sandbox network denial, clean environment, filesystem confinement,
resource ceilings, cancellation, process-group termination, and artifact
binding. Signed NuGet verification runs during every helper build.

## Migration, recovery, and rollback

- Enable the helper only after CYB-97 returns a fresh qualified Sentinel
  capability and complete schema bound to the exact workspace identity.
- Admit only a separately publisher-signed tool manifest whose artifact,
  runtime, package closure, registry, operation, T0 tier, and `network:none`
  policy match this qualification.
- On any version or policy change, revoke retained validations and execution
  plans, rebuild all Tier 1 RIDs, rerun the full corpus, and require fresh schema
  discovery before re-enabling validation.
- Recovery always starts from current authority and a newly verified immutable
  artifact. It never adopts partial stdout, stderr, temporary files, old schema,
  old audit proof, or unsigned fallback.
- Rollback disables Sentinel dispatch, revokes the affected manifest/policy and
  retained results, and restores a prior separately signed and qualified helper
  only through ordinary admission and a new conformance run.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Signed network-denied semantic helper and AST-derived bound | Helper manifest, SBOM/provenance, managed conformance, signed-registry and native-sandbox tests | Pass |
| Default deny, actor/scope binding, redaction, audit, replay/tamper/stale/revocation | Go service, closed evidence fixtures, adversarial trace | Pass |
| Invalid, denial, timeout/cancel, outage and recovery without bypass | Contract, managed, service, native-runner, and replay suites | Pass |
| Applicable CI, race, architecture, secret, license, dependency and size gates | Clean promotable baseline report and focused verifier | Pass |
| Checksummed adversarial, decision, audit, denial, revocation, manifest, SBOM and provenance evidence | `CYB-98-artifacts.sha256` | Pass |

No CYB-98 blocking finding remains. The approved product-level follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
