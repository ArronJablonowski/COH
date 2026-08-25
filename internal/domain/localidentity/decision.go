package localidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func decisionFor(actor Actor, request Request) Decision {
	return Decision{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, PayloadDigest: request.PayloadDigest,
		Channel: request.Channel, Context: request.Context, Permission: request.Permission,
		ActionTier: request.ActionTier, ActorRevision: actor.Revision,
	}
}

func finalizeDecision(decision Decision) Decision {
	decision.DecisionDigest = ""
	encoded, err := json.Marshal(decision)
	if err != nil {
		panic("local identity decision contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision
}

func errorReason(err error) string {
	if typed, ok := err.(*IdentityError); ok {
		return typed.Reason
	}
	return "invalid_input"
}
