# Native llama.cpp server adapter v1

This package owns the only llama.cpp wire vocabulary used by COH. Vendor
objects never cross the adapter boundary; callers provide and receive validated
`providercontract` documents.

## Frozen API surface

- Upstream contract: llama.cpp commit
  `5d5cb4c3a4ea8769490d39a275ee49a45184774d`.
- Exact loopback origin: `http://127.0.0.1:8080`.
- Allowed operations: read-only `GET /health`, `GET /props`,
  `GET /v1/models`, and inference-only `POST /v1/chat/completions`.
- Adapter version: `1.0.0`; vendor surface:
  `llama.cpp.server.chat-completions/5d5cb4c`.
- Health, properties, and model probes bind the build fingerprint, model alias
  and path, effective context, GGUF metadata, active chat template and parser
  capabilities to the qualified provider tuple before every chat request.
- A managed local-route verifier independently hashes the llama-server binary
  and GGUF file and attests that router, model autoload/download, agent, MCP,
  vendor tool execution, remote media, mutable properties, and non-loopback
  serving are disabled. Loopback reachability is not identity evidence.
- Chat requests use only typed messages, broker-owned strict function tools,
  documented JSON-schema response constraints, bounded sampling fields,
  `cache_prompt:false`, and explicit tool parsing and streaming behavior.
- Structured output and tool calling are not combined because llama.cpp uses
  competing grammar modes for those paths; the adapter returns `unsupported`
  instead of silently changing either constraint.
- Streaming accepts only bounded `data:` SSE records with stable completion ID,
  creation time, model alias, and build fingerprint. A finish chunk, usage and
  timing chunk, and `[DONE]` marker are all required.
- No credentials, ambient proxy, redirects, alternate origins, remote media,
  generic vendor options, log probabilities, mutable/admin routes, or hidden
  partial success are permitted.

Any new field, route, enum member, upstream build, GGUF digest, template,
capability set, parser behavior, context setting, launch mode, or adapter change
is unsupported until its fixture, denial tests, and signed qualification are
reviewed.
