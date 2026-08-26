# Provider contract v1 compatibility matrix

| Change or observation | Compatibility | Required action |
|---|---|---|
| Add a provider implementation for the unchanged v1 contract | Potentially additive | Run every mandatory qualification case for the exact provider tuple |
| Add a model, endpoint, platform, route, hardware profile, or state mode | New support claim | Create a distinct passing qualification record before admission |
| Change model revision/weights, runtime, tokenizer, template, parser, adapter, capability, route, hardware, or policy revision | Material change; old evidence invalid | Requalify the complete tuple and preserve the prior record |
| Add a message/content/tool/event/error kind or required field | Incompatible | Publish a new schema and contract version; use parallel readers during migration |
| Add an optional field not known to a v1 reader | Denied | New contract version and explicit mixed-reader qualification |
| Remove, rename, reinterpret, or relax a field or bound | Incompatible | New major contract version, migration, replay assessment, and security review |
| Change COH-CJ-1, a digest domain, or set/sequence semantics | Incompatible | New contract and digest identity; requalify every tuple |
| Unknown schema, contract, provider kind, capability, role, item, state, route, event, outcome, or error | Denied | Upgrade through reviewed versioned change control |
| Qualification expired or a bound tuple field differs | Unsupported | Deny admission and run a new qualification |
| One mandatory conformance case is missing, failed, or references another fixture/trace | Unsupported | Repair and rerun the complete suite; no partial support claim |
| Same qualification ID with different canonical bytes | Conflict | Preserve the original record and issue a new ID |
| Same request/attempt ID with different canonical bytes | Conflict | Preserve the original attempt; retry with a new attempt ID |
| Provider returns a capability or result outside the qualified snapshot | Denied | Stop dispatch, record drift, and invalidate the qualification |
| Runtime policy narrows an otherwise qualified capability | Compatible narrowing | Record the denial; qualification never widens policy |

Successful JSON decoding, HTTP health, model-name equality, endpoint reachability,
or a passing subset of cases never implies compatibility or qualification.
