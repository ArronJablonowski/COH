# CYB-8 E06 execution-boundary integration verification report

| Field | Value |
|---|---|
| Issue | COH-E06 / CYB-8 |
| Requirements | SEC-005, SEC-018, SEC-017, NFR-002, SEC-031, SEC-032, SEC-012, SEC-024, SEC-025, FR-076, SEC-029, EVAL-008 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `ac786a18712bdc507d039ac369a2ee02ae8a803d` |
| Aggregate result | Pass |

## Outcome

The five COH-E06 leaves form one default-deny execution boundary. Tool
operations enter through a strict signed registry contract, resolve to a
reviewed typed operation, and can run only in the operation's authorized
`native_restricted`, `oci_sandbox`, or `remote_isolated` zone. The native and
OCI executors resolve the actual signed registry and require fresh trusted
authorization before creating an execution plan. Remote dispatch requires an
authenticated enrolled worker and an exact, short-lived, single-use runner
lease bound to the signed registry digest, tool operation, action tier,
isolation class, resources, network policy, actor, task, case, and current
policy and approval decisions.

Native execution admits only T0/T1 operations with fixed argv, typed stdin,
a clean bounded environment, no network, a staged digest-verified executable,
a confined working directory, and bounded process resources. OCI execution
admits T0-T3 operations with a digest-pinned image, fixed entrypoint, non-root
identity, read-only root filesystem, dropped capabilities, bounded tmpfs,
broker-attested network lease, and no host mount, engine socket, credential
injection, or caller-controlled container surface. Remote execution binds the
attested worker's exact isolation, resource ceiling, network modes, runtime,
executor, and registry digests; no lease capability or credential value enters
the serializable dispatch envelope.

The emergency stop is authoritative across the same boundary. It rejects or
revokes credential and runner leases within one second, cuts broker-owned OCI
egress within two seconds, cancels remote jobs and signals durable workflows
within five seconds, and requests cooperative native, OCI, and remote
termination within ten seconds.

## Integration acceptance mapping

| Integration criterion | Authoritative evidence | Result |
|---|---|---|
| Every tool runs through a registered typed adapter in an authorized execution zone | Strict signed-registry contract and denial corpus; actual-registry native and OCI integration tests; exact remote registry/tool/operation/tier/isolation lease bindings; public-surface tests prohibit generic execution primitives | Pass |
| Native, OCI, and remote workers enforce lease, resource, network, filesystem, and credential restrictions | Native sandbox isolation/resource/filesystem/network tests; OCI least-privilege plan, runtime, mount, network-lease, and credential-injection denial tests; remote single-use lease, attestation ceiling, exact resource/network/isolation, redaction, and revocation tests | Pass |
| E-stop meets lease, egress, workflow-signal, and cooperative-termination objectives | Mandatory stop guards and containment dependencies; native/OCI/remote integration tests; deterministic monotonic 1/2/5/10-second conformance harness | Pass |

## Cross-boundary verification

`scripts/verify_e06_integration.sh` reruns all five leaf verifiers and then
executes focused integration paths:

- native signed-registry sandbox execution, network/filesystem denial, and
  cooperative E-stop cancellation;
- OCI actual signed-registry resolution with live publisher authority,
  least-privilege plan construction, network lease enforcement, and E-stop;
- remote lease issuance and single-use dispatch, policy/approval/cancellation
  and redaction behavior, and scoped E-stop lease revocation; and
- global containment fan-out plus the monotonic timing conformance suite.

Every leaf verifier also runs its applicable unit, repeated, race, vet,
cross-platform compilation, schema, secret-surface, architecture, file-size,
and diff gates. The integrated run finished with:

```text
E06 integration summary: registry=signed+typed authorization=fresh zones=native_restricted+oci_sandbox+remote_isolated native=resource+network+filesystem+credential-deny OCI=resource+network+filesystem+credential-deny remote=lease+resource+network+isolation estop=1s+2s+5s+10s evidence=5-leaves failures=0
```

The retained clean log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/e06-integration.L9Ddem/e06-integration.log
SHA-256 3377b422500e856fb09f1f6769fc6eeabd73650a7d04918db21e8b1c3de9be4e
```

Its architecture checks report 54 packages and zero violations. Provenance
records `ac786a1`, `modified:false`, Go 1.26.7, and darwin/arm64.

## Leaf evidence

| Leaf | Capability | Result |
|---|---|---|
| CYB-53 / COH-E06-01 | Signed tool registry | Pass |
| CYB-54 / COH-E06-02 | Low-risk native executor | Pass |
| CYB-55 / COH-E06-03 | Optional OCI executor | Pass |
| CYB-58 / COH-E06-04 | Remote-worker enrollment and leases | Pass |
| CYB-57 / COH-E06-05 | Containment and E-stop | Pass |

Each leaf has a committed report and checksum manifest under
`docs/evidence`. The integration verifier refuses to run if any report,
manifest, or recorded aggregate Pass result is missing.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.qPCF33/quality-report.json
```

The embedded report digest is
`19bc30aeb8cad997e86d5e8f59ecb8e80033a898ac616c7bce52f477d6616a1e`;
the report-file SHA-256 is
`c4a66b941ac57afd531f9573471204b923cc6700fcf032a5cdac55c18faaf7ef`.
Provenance records 724 source files, source digest
`43eb005f6abb5c163db3a94b70fc977d73ce6099570420a87e39400a6cb823a5`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Security-boundary interpretation

The remote-worker boundary proves authenticated enrollment, signed software
capability attestation, exact lease binding, and broker-side authorization,
revocation, and dispatch controls. It does not claim TPM, measured-boot, TEE,
or physical-host attestation. The current in-memory remote-worker store is a
single-control-plane implementation; multi-replica deployment requires a
durable atomic store. E-stop durability is supported for a single-node SQLite
profile; multi-replica deployment requires linearizable state and workflow
indexes.

These deployment-profile limits do not weaken the tested single-node E06
boundary. They must be resolved before claiming the corresponding distributed
deployment profile.

## Reproduction

```sh
./scripts/verify_e06_integration.sh
./scripts/run_ci_quality.sh baseline
```

## Release gate

Independent security architecture review remains a hard gate before the first
production release under CYB-173. It is not a blocker for completing the
development and integration acceptance of COH-E06.
