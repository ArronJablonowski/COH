# llama.cpp provider capability v1

This recorded capability is the public COH contract fixture for CYB-59 and
FR-034, FR-037, and FR-038. It describes a qualified native llama.cpp server
profile, not a promise that arbitrary OpenAI-compatible servers are accepted.

The fixture is bound to adapter version `1.0.0`, the exact loopback endpoint,
the pinned server surface, a GGUF revision, build identity, model metadata,
effective context, active chat template, parser identities, hardware profile,
sampling profile, policy revision, and stateless local route.

Production qualification replaces fixture identities with measured values and
requires the managed route verifier to independently hash the llama-server
binary and GGUF file and attest the launch configuration. The capability is
invalid after `valid_until` and is not itself a production qualification.
