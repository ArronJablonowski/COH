# COH Kusto.Language helper

This directory contains the only approved Kusto.Language process. It is a
credentialless parser/compiler launched through COH's signed native executor as
T0 with `network:none`. It has no generic command, argument, file, environment,
credential, endpoint, or network surface.

The helper performs `KustoCode.ParseAndAnalyze` against an exact closed
`GlobalState` built from the request schema. It defaults to denial for every
unlisted operator or resolved function, rejects wildcard/fuzzy union and remote
entity paths, denies dynamic/open output, and constructs its terminal `take`
as a cloned `PipeExpression`/`TakeOperator` tree. The formatted tree is reparsed
and reanalyzed, and its non-terminal structural fingerprint and semantic
inventory must match before canonical KQL can leave the process.

The project pins .NET SDK 10.0.400, runtime 10.0.11, and
`Microsoft.Azure.Kusto.Language` 12.4.1. Restore is locked and requires signed
packages. Supported self-contained single-file RIDs are `osx-arm64`,
`linux-x64`, and `linux-arm64`.

Native executor input is a closed eight-field chunk envelope because the signed
tool registry intentionally has no generic nested-JSON input type. Concatenated
chunks form exactly one `coh.kusto-helper-request/v1` document. Chunks must be
contiguous, each is at most 61,440 characters, and the decoded document remains
bounded to 1 MiB. The helper rejects duplicate keys at every nesting level and
unknown fields before semantic processing.

Build and verification use `scripts/build_kusto_validator.sh` and
`scripts/verify_kusto_validator.sh`. Build products and package caches remain in
the external COH toolchain root, not the repository. See
`docs/design/kusto-language-validator.md` and
`contracts/kusto-validator/v1/README.md` for the normative boundary.
