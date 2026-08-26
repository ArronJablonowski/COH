# Qualified vLLM provider adapter

This package implements the COH provider contract for a managed, stateless
vLLM OpenAI-compatible server. The supported vendor surface is frozen to vLLM
commit `796822d141382ab8ce82ef6101c6d802046f94e0`.

Trust boundary:

- The only origin is `http://127.0.0.1:8000`; proxies, redirects, TLS,
  credentials, alternate hosts and alternate ports are rejected.
- The only operations are `GET /health`, `GET /version`, `GET /v1/models`,
  opt-in read-only `GET /tokenizer_info`, and `POST /v1/chat/completions`.
- Health must be an empty 200 response. Version, one served model/root/context,
  the complete tokenizer configuration, and chat template are observed before
  every dispatch and compared with the qualified capability.
- The managed route verifier independently attests the vLLM package and image,
  model weights, CUDA/PyTorch/GPU topology, exact tool and reasoning parsers,
  launch flags, disabled dev mode and mutation surfaces, and stateless mode.
- Requests contain only broker-owned messages, strict function schemas,
  strict JSON-schema output and bounded sampling fields. There is no generic
  header, body, media, parser, template, priority or extension passthrough.
- Responses and SSE frames use exact typed shapes. Provider-only tracing,
  transfer, prompt, logprob, routed-expert, remote-media and metrics fields are
  rejected when populated. Raw canonical responses remain provenance-bound.

Explicitly unsupported surfaces include `/invocations`, `/server_info`, model
or prompt-adapter mutation, weight/cache/profile/RPC mutation, parser plugins,
remote media, provider-managed conversation state, ambiguous model aliases and
unqualified runtime, template, tokenizer, parser or GPU drift.

Any route, field, enum, upstream revision, runtime/image/model digest, tokenizer
configuration, chat template, parser, GPU topology or launch-state change
requires a new capability snapshot and signed qualification.
