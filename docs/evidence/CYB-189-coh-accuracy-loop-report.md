# CYB-189 COH accuracy-loop implementation report

## Scope

This evidence packet covers the first production implementation slice of the
COH accuracy and cyber-workflow leadership plan. It is not a claim that the
statistical leadership gate has been met; repeated exact-matched qualification
remains a separate release gate.

## Implemented controls

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Versioned task and output contract | `TaskContract`, capability requirements, safety boundary, validator profile, repair policy | Contract/profile unit tests |
| Qualified model execution profile | Exact digest/capability-bound `ModelExecutionProfile` and stable prompt compiler | Capability, digest, reasoning, and prompt-boundary tests |
| Native structured generation | Ollama JSON Schema change-set request with exact response identity and usage checks | Recorded workspace/provider tests and CLI build |
| External deterministic validation | Allowlisted validator registry for code and cyber artifacts | Registry, path, symlink, fence, and diagnostic tests |
| At most three calls | Generate, validate, then up to two diagnostic-guided repairs | Three-attempt exhaustion and provenance tests |
| No repeated side effects | Confirmed/uncertain action artifacts stop immediately | Side-effect repair denial tests |
| Fail-closed security behavior | Exhausted security-sensitive contracts reject; advisory output is explicitly incomplete | Disposition tests |
| Supported entrypoint | `cmd/coh-agent` with exact model digest, workspace, contract, timeout, JSON result | CLI package tests and Studio binary verification |

## Design lineage

The implementation follows COH's existing durable plan/act/observe/review and
authority boundaries. Prompt composition and model qualification adopt the
production patterns described by Hermes Agent, OpenClaw, Pi Agent, and Ollama,
without benchmark-specific answer transformations:

- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/architecture.md
- https://github.com/openclaw/openclaw/blob/main/docs/concepts/agent-loop.md
- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md
- https://docs.ollama.com/capabilities/structured-outputs
- https://docs.ollama.com/api/chat
- https://docs.ollama.com/capabilities/thinking

## Remaining release evidence

The benchmark repository owns exact-digest competitor matching, capability
exclusions, Standard-v2 contract corrections, repeated trials, paired bootstrap
confidence intervals, ablations, held-out fixture mutations, and HTML reporting.
CYB-189 remains open until the best-competitor paired 95% confidence interval is
strictly above zero and all safety and regression gates pass.
