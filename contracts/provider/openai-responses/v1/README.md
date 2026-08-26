# COH OpenAI Responses capability fixture

This directory publishes the bounded capability snapshot exercised by the
CYB-62 adapter qualification tests. It is a deterministic recorded conformance
tuple, not a claim that an arbitrary OpenAI model or alias is qualified for
production.

The snapshot binds adapter version `1.0.0`, the exact approved Responses API
endpoint identity, approved external routing, model and parser identities,
stateless encrypted reasoning, policy revision, and all resource limits. Its
provider-contract digest is:

```text
sha256:70325fbd315daee428cc4b4aef1e785d11a29594336325621de6861ef5bba28c
```

Runtime dispatch still requires an unexpired signed provider qualification in
the trusted `QualificationRegistry`. Endpoint reachability and a matching model
name never qualify a tuple.

Any material endpoint, route, model revision, runtime, tokenizer, parser,
sampling, hardware, state-mode, policy, adapter, or limit change requires a new
snapshot and qualification record.
