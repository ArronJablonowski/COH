# CYB-205 Muse Glimmer production-path smoke evidence

## Scope

This is a one-model, one-task readiness observation for the repeated paired
cybersecurity campaign. It is not a leadership result and does not satisfy the
three-repetition qualification gate.

## Frozen identities

- COH commit: `cc17e05`
- COH binary SHA-256: `0ba7b8dae2ce5bf0403289ef404fcebb43412dd8765087628a77731818ece7cb`
- Benchmark-suite commit: `e28e7cc`
- Benchmark profile: `cybersecurity-agent-v1`
- Model: `muse-glimmer:30b-mlx`
- Ollama model digest: `ef32a55b4976faa955cbab0462d09bd081351ef5b87d73d8fcd299bf17c111d7`
- Task: `cyber_sigma_detection`

## Result

- Runner status: `ok`
- Strict verdict: `pass`
- Checks: `10/10`
- Wall time: `25.610s`
- Model calls: `1`
- Repair calls: `0`
- Validator accepted: `true`
- Changed artifacts: `detection.yml`, `submission.json`
- Task-contract digest: `sha256:98ea0f7f8c7fc28b2b5dc1d0d5ff7ec76eddcf67bd73b112fe9fc68ea6c7d8dc`
- Execution-profile digest: `sha256:461b578259e451ab17611020b40a43c52880b818cc77fc287385a38ecc74c0b4`
- Agent-provenance digest: `sha256:ecd3168dd65364f36d381aefca1f046ae90bf31b18bcf93281c4c19756081855`

## Defects found and corrected

1. The benchmark's Linux-only OOM/swap and daemon-identity guards were applied
   unconditionally on macOS. Benchmark commits `e6dfa8e` and `e28e7cc` retain
   Linux fail-closed checks and use the native platform sampler off Linux.
2. Ollama reports model identity as raw lowercase SHA-256 hex while COH's
   internal execution profile requires the `sha256:` form. COH commit
   `d69591d` validates the raw identity and qualifies it at the contract edge.
3. Muse Glimmer advertised structured output but ignored Ollama's `format`
   schema and returned fenced prose. Its native tool-call surface honored the
   exact schema. COH commit `cc17e05` requires one `submit_change_set` call and
   rejects prose, duplicate calls, unknown fields, and trailing data.

## Verification

The final COH checkpoint passed `go test -count=1 ./...`, `go vet ./...`, and
all-package staticcheck. Focused agent tests also passed repeated and race runs.
The benchmark macOS guard regressions passed 21 focused unit tests.

## Next gate

Run fresh, immutable output directories for at least three complete repetitions
per exact model/task/harness cell, preserve all terminal outcomes, then compute
the paired-bootstrap confidence interval and the required ablations.
