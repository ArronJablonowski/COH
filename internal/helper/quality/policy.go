package quality

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

var requiredLanes = []Lane{
	{ID: "baseline", GoVersion: "1.26.7", Enforcement: "required"},
	{ID: "go1.27", GoVersion: "1.27.0", Enforcement: "qualification"},
}

var requiredStageSpecs = []StageSpec{
	{ID: "format", TimeoutSeconds: 60}, {ID: "file-size", TimeoutSeconds: 120},
	{ID: "workflow", TimeoutSeconds: 120},
	{ID: "secret-worktree", TimeoutSeconds: 120}, {ID: "secret-history", TimeoutSeconds: 120},
	{ID: "architecture", TimeoutSeconds: 120}, {ID: "quality-contract", TimeoutSeconds: 180},
	{ID: "vet", TimeoutSeconds: 120},
	{ID: "static-analysis", TimeoutSeconds: 180}, {ID: "unit", TimeoutSeconds: 180},
	{ID: "race", TimeoutSeconds: 300}, {ID: "fuzz-seed", TimeoutSeconds: 120},
	{ID: "license", TimeoutSeconds: 120}, {ID: "dependency", TimeoutSeconds: 300},
	{ID: "sbom", TimeoutSeconds: 120}, {ID: "supply-chain", TimeoutSeconds: 300},
	{ID: "secret-evidence", TimeoutSeconds: 120},
	{ID: "provenance", TimeoutSeconds: 120},
}

var requiredStages = stageIDs(requiredStageSpecs)

// DecodePolicy strictly parses the closed v1 quality policy.
func DecodePolicy(data []byte) (Policy, error) {
	if len(data) == 0 || len(data) > MaximumPolicySize {
		return Policy{}, qualityError(CodeInvalidInput, "policy", "policy size is invalid", nil)
	}
	var policy Policy
	if err := decodeStrict(data, &policy); err != nil {
		return Policy{}, qualityError(CodeInvalidInput, "policy", "invalid policy JSON", err)
	}
	if err := ValidatePolicy(policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func ValidatePolicy(policy Policy) error {
	if policy.SchemaVersion != PolicySchema {
		return qualityError(CodeInvalidInput, "schema_version", "unsupported policy schema", nil)
	}
	if policy.PolicyVersion != "1.2.0" {
		return qualityError(CodeInvalidInput, "policy_version", "reader supports 1.2.0", nil)
	}
	if !slices.Equal(policy.Lanes, requiredLanes) {
		return qualityError(CodeDenied, "lanes", "baseline and qualification lanes are locked", nil)
	}
	if !slices.Equal(policy.Stages, requiredStageSpecs) {
		return qualityError(CodeDenied, "stages", "the complete fixed stage set is required", nil)
	}
	return nil
}

func stageIDs(specifications []StageSpec) []string {
	identifiers := make([]string, len(specifications))
	for index, specification := range specifications {
		identifiers[index] = specification.ID
	}
	return identifiers
}

func SelectLane(policy Policy, id string) (Lane, error) {
	for _, lane := range policy.Lanes {
		if lane.ID == id {
			return lane, nil
		}
	}
	return Lane{}, qualityError(CodeInvalidInput, "lane", "unknown CI lane", nil)
}

func CanonicalPolicy(policy Policy) ([]byte, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

func PolicyDigest(policy Policy) (string, error) {
	canonical, err := CanonicalPolicy(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON is forbidden")
	}
	return nil
}
