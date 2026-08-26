# vLLM provider contract v1

`capability.json` is the public qualification snapshot for the narrow vLLM
adapter in `internal/provider/vllm`. It binds the exact loopback endpoint,
served model, model revision, vLLM runtime/image identity, tokenizer
configuration, chat template, tool parser, reasoning parser, hardware profile,
sampling profile, state mode and resource limits.

The HTTP probes cannot establish package/image, model-weight, CUDA/PyTorch/GPU,
parser implementation or launch-state integrity. Production construction must
therefore supply a managed verifier that independently attests the complete
tuple and rejects dev mode, `/invocations`, dynamic adapters, mutation APIs,
remote media and any non-stateless or non-loopback serving mode.

The recorded values are deterministic qualification fixtures, not permission
to deploy those placeholder digests. A deployment must publish and sign a
capability containing its independently measured values before dispatch.
