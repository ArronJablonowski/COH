# COH-E11 integration verifier

This package verifies the exact digest and scope chain across CYB-80 normalized
events, CYB-81 mapping outcomes, CYB-82 time records/comparisons, CYB-83 entity
observations/revisions, and CYB-86 investigation facts and projections.

`Verify` independently canonicalizes every leaf record, checks all cross-leaf
bindings, and replays all three reducers. It fails closed on mapping, entity,
time, projection, scope, version, fact-chain, or watermark drift. The boundary
accepts no raw evidence source, policy source, credential, connector, executor,
provider, model, network, filesystem, SQL, shell, or generic callback.

Migration, recovery, rollback, privacy, compatibility, and bounded-dataset
rules are frozen in the
[COH-E11 integration design](../../../docs/design/e11-integration.md).
