package deploymentprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func newDecision(config Config, configDigest, outcome, reason string) Decision {
	decision := Decision{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ConfigDigest: configDigest, Outcome: outcome, ReasonCode: reason,
		OrganizationID: config.Change.OrganizationID, ActorID: config.Change.ActorID, Revision: config.Change.Revision,
		Deployment: config.Deployment.Kind, Connectivity: config.Connectivity.Mode,
	}
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func invalidDecision(reason string) Decision {
	decision := Decision{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, Outcome: "invalid", ReasonCode: reason}
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func canceledDecision(err error) Decision {
	reason := "context_canceled"
	if Code(err) == Timeout {
		reason = "context_deadline"
	}
	decision := Decision{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, Outcome: string(Code(err)), ReasonCode: reason}
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func decisionDigest(decision Decision) string {
	decision.DecisionDigest = ""
	encoded, err := json.Marshal(decision)
	if err != nil {
		panic("deployment profile decision contains only JSON-safe fields")
	}
	return digestBytes(encoded)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
