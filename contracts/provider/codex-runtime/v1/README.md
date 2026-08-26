# Codex runtime provider contract v1

`capability.json` records the qualified App Server tuple: Codex binary,
generated v2 protocol, model/revision, managed configuration, route,
environment, parser behavior, stateless ephemeral thread mode, and bounds.

Production construction must supply a managed App Server launcher, batch
runner, credential channel, and tool broker. The bridge contains no permissive
launcher, ambient credential discovery, generic JSON-RPC passthrough, or
automatic App Server-to-exec fallback.

The contract implements COH-E07-06 / CYB-61 and records the FR-036 external
agent/batch boundary and FR-039 exact-route, no-silent-failover guarantee.
