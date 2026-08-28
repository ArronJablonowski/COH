# Architecture contract v1 fixtures

This bundle belongs to COH-E02-01 / CYB-32 and is validated by the
`internal/helper/architecture` tests.

| Artifact | Expected result |
|---|---|
| `workspace-contract.json` | Valid v1 source contract |
| `workspace-contract.schema.json` | Draft 2020-12 external schema |
| `fixtures/valid/workspace-contract.canonical.json` | Exact `COH-JSON-C14N-1` bytes, allowing one text-file newline |
| `fixtures/valid/allowed-graph.json` | Allowed dependency report |
| `fixtures/invalid/malformed.json` | `invalid_input` |
| `fixtures/invalid/unknown-field.json` | `invalid_input` |
| `fixtures/invalid/unsupported-version.json` | `unsupported_version` |
| `fixtures/invalid/forbidden-graph.json` | Workflow/provider connector bypass denied |
| `fixtures/invalid/command-broker-bypass.json` | Command connector/policy composition denied |
| `fixtures/invalid/remote-connector-bypass.json` | Remote transport connector bypass denied |
| `fixtures/invalid/capability-composition-bypass.json` | Compiled `ARCH-003` denies non-control-plane composition imports |
| `fixtures/invalid/profile-composition-bypass.json` | Compiled `ARCH-004` denies profile composition outside the command root |
| `fixtures/invalid/extension-lifecycle-bypass.json` | Compiled `ARCH-005` denies workflow, agent, provider, and transport lifecycle control |
| `fixtures/invalid/go-mod-*.txt` | Module, Go/toolchain, and replace drift denied |
| `fixtures/invalid/go-work-*.txt` | Extra workspace use and replace drift denied |

Negative fixtures are data, never executable source. The checker does not modify
them, downgrade them, or recover by weakening the contract.
