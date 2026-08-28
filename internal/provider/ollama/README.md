# Native Ollama adapter v1

This package owns the only native Ollama wire vocabulary used by COH. Vendor
objects never cross the adapter boundary; callers provide and receive validated
`providercontract` documents.

## Frozen API surface

- Exact loopback origin: `http://127.0.0.1:11434`.
- Allowed operations: `GET /api/version`, `GET /api/tags`,
  `POST /api/show`, and `POST /api/chat`.
- Adapter version: `1.1.0`; vendor surface: `ollama.native.chat/v2`.
- `/api/version`, `/api/tags`, and `/api/show` must bind the runtime version,
  served model name and digest, chat template, advertised capabilities, model
  metadata, and context limit to the qualified provider tuple before chat.
- Current Ollama runtimes may publish sparse tag details for MLX/safetensors
  models. Absent tag fields are completed from `/api/show`; every tag field
  that is present must match, and the combined metadata remains digest-bound.
- Chat uses native messages, strict function tools, a JSON schema in `format`,
  bounded generation options, `keep_alive:0`, and explicit streaming mode.
- Streaming uses newline-delimited JSON. Chunks must retain the exact model and
  response correlation and must end in one `done:true` record.
- The local profile sends no authorization header and rejects redirects,
  ambient proxies, alternate origins, cloud routes, generic options, images,
  log probabilities, and undocumented fields.
- Every dispatch requires a managed-runtime attestation that the observed
  Ollama process is cloud-disabled for the exact runtime/model digest tuple;
  loopback reachability by itself is not proof of local data residency.

Ollama does not strictly version its native API. Any new field, enum member,
runtime version, model digest, template, capability set, parser behavior,
context setting, route, or adapter change is unsupported until its fixture,
translation, denial tests, and signed qualification are reviewed.

`benchmark_command_test.go` can be compiled with `go test -c` as a test-only
local invocation surface for reproducible benchmarks. Its ephemeral signed
qualification is not a production qualification or a substitute for
independent security review.
