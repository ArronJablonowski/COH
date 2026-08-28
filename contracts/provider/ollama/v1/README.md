# COH native Ollama capability fixture

This directory publishes the bounded capability snapshot exercised by the
CYB-63 adapter qualification tests. It is a deterministic recorded conformance
tuple, not a claim that an arbitrary Ollama host, model tag, or model alias is
qualified for production.

The snapshot binds adapter version `1.1.0`, the exact loopback origin and
four-operation native API surface, Ollama runtime version, served model digest,
chat template, model metadata/tokenizer digest, context, parser identities,
sampling profile, hardware profile, policy revision, state mode, and resource
limits. Its provider-contract digest is:

```text
sha256:d4e74c3367e8defcbd8e129ce507fcb5074b0a53151818714c4ef3d0563a57c5
```

Runtime dispatch still requires an unexpired signed provider qualification and
must re-observe matching `/api/version`, `/api/tags`, and `/api/show` identity
before `/api/chat`. Reachability or a matching model tag never qualifies a
tuple. Dispatch also requires the managed deployment boundary to attest that
the observed loopback runtime is cloud-disabled for this model digest.

Any material runtime, model digest, template, model metadata, tokenizer,
parser, context, sampling, hardware, route, policy, adapter, capability, or
limit change requires a new snapshot and qualification record.
