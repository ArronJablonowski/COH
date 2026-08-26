# OpenAI Responses adapter v1

This package owns the only OpenAI vendor wire vocabulary used by COH. Vendor
objects never cross the adapter boundary; callers provide and receive validated
`providercontract` documents.

## Frozen API surface

- Exact operation: `POST https://api.openai.com/v1/responses`.
- Adapter version: `1.0.0`; vendor surface: `openai.responses.create/v1`.
- Exact request invariants: `store:false`, `background:false`,
  `truncation:"disabled"`, bounded `max_output_tokens`, and no conversation,
  metadata, prompt template, built-in tool, MCP tool, hosted tool, or generic
  vendor option.
- Function tools are the only tool category. Tool input and structured-output
  schemas are resolved from trusted digest-addressed storage and sent strict.
- Stateless reasoning uses `include:["reasoning.encrypted_content"]`; encrypted
  reasoning items are retained behind digest-addressed references for an
  explicitly supplied later turn.
- Supported output items are `message`, `function_call`, and `reasoning`.
  Message content is limited to `output_text` and `refusal`.
- Supported terminal statuses are `completed`, `failed`, `incomplete`, and
  `cancelled`. `queued` or `in_progress` is a protocol violation because the
  adapter disables background execution.
- Unknown fields, item kinds, content kinds, statuses, model drift, route drift,
  malformed JSON, sequence disorder, oversized bodies, and partial transport
  reads fail closed.

OpenAI function calls are returned to the workflow as typed intents only. The
adapter never executes a function and exposes no action-capable dependency.

## Compatibility

New vendor fields or enum members are unsupported until recorded fixtures,
translation rules, denial tests, and qualification evidence are reviewed. A
model, endpoint, route, adapter, parser, tokenizer, policy, or runtime change
creates a different provider tuple and invalidates existing qualification.
