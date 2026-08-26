package estop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func DecodeCommand(input []byte) (Command, error) {
	var command Command
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return command, NewError(InvalidInput, "command_decoding")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return command, NewError(InvalidInput, "command_decoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return Command{}, NewError(InvalidInput, "command_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Command{}, NewError(InvalidInput, "command_decoding")
	}
	if err := ValidateCommand(command); err != nil {
		return Command{}, err
	}
	return command, nil
}

func CommandDigest(command Command) (string, error) {
	if err := ValidateCommand(command); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return "", NewError(InvalidInput, "command_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", NewError(InvalidInput, "command_encoding")
	}
	return digestBytes(canonical), nil
}

func FinalizeDecision(decision Decision) Decision {
	decision.SchemaVersion, decision.ContractVersion, decision.DecisionDigest = DecisionSchemaVersion, ContractVersion, ""
	encoded, _ := json.Marshal(decision)
	decision.DecisionDigest = digestBytes(encoded)
	return decision
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
