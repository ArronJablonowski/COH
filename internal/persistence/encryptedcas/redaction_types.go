package encryptedcas

import "context"

// RedactionRuleMaterial is trusted adapter-only replacement material. It is
// resolved by signed rule digest and never crosses the workflow contract.
type RedactionRuleMaterial struct {
	RuleDigest string
	Mask       []byte
	Token      []byte
}

type RedactionRuleResolver interface {
	ResolveRedactionRule(context.Context, string) (RedactionRuleMaterial, bool, error)
}
