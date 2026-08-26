package agentloop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	provenanceDomain = "COH-AGENT-LOOP-PROVENANCE-V1\x00"
	intentDomain     = "COH-AGENT-LOOP-INTENT-V1\x00"
	receiptDomain    = "COH-AGENT-LOOP-RECEIPT-V1\x00"
)

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "canonical", "value_encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "canonical", "value_not_canonicalizable", false, nil)
	}
	return canonical, nil
}

func digestValue(domain string, value any) (string, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return digestBytes(domain, canonical), nil
}

func digestBytes(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func transitionDigest(prior, operation string, value any) (string, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return digestBytes(provenanceDomain, append([]byte(prior+"\x00"+operation+"\x00"), canonical...)), nil
}

func toolIntentDigest(intent domain.ToolIntent) (string, error) {
	return digestValue(intentDomain, struct {
		OperationID    string         `json:"operation_id"`
		Case           domain.CaseRef `json:"case"`
		Tool           string         `json:"tool"`
		Action         string         `json:"action"`
		TargetDigest   string         `json:"target_digest"`
		ArgumentDigest string         `json:"argument_digest"`
	}{intent.OperationID, intent.Case, intent.Tool, intent.Action, intent.TargetDigest, intent.ArgumentDigest})
}

// ToolIntentDigest returns the exact digest consumed by authorized-action
// steps so upstream typed planners can bind a plan to one broker intent.
func ToolIntentDigest(intent domain.ToolIntent) (string, error) {
	return toolIntentDigest(intent)
}

func actionReceiptDigest(receipt domain.ActionReceipt) (string, error) {
	return digestValue(receiptDomain, struct {
		IntentDigest string             `json:"intent_digest"`
		Outcome      string             `json:"outcome"`
		Evidence     domain.ArtifactRef `json:"evidence"`
	}{receipt.IntentDigest, receipt.Outcome, receipt.Evidence})
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > 1<<20 {
		return newError(Denied, "decode", "record_size_invalid", false, nil)
	}
	if _, err := domaincontract.DecodeUnique(input); err != nil {
		return newError(Denied, "decode", "record_duplicate_or_malformed", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "decode", "record_malformed", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "decode", "record_trailing_data", false, nil)
	}
	return nil
}
