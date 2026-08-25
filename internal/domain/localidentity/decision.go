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

// NewDecision creates a digest-bound, redacted decision for a transport
// failure that occurs before an actor record is available.
func NewDecision(request Request, actorRevision uint64, outcome, reason string) Decision {
	decision := decisionFor(Actor{Revision: actorRevision}, request)
	decision.Outcome = outcome
	decision.ReasonCode = reason
	return finalizeDecision(decision)
}

// BindSession adds the non-secret session correlation identifier and replay
// state to a decision, then recomputes its integrity digest.
func BindSession(decision Decision, sessionID string, replayed bool) Decision {
	decision.SessionID = sessionID
	decision.Replayed = replayed
	return finalizeDecision(decision)
}

func errorReason(err error) string {
	if typed, ok := err.(*IdentityError); ok {
		return typed.Reason
	}
	return "invalid_input"
}
