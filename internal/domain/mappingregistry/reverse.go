package mappingregistry

import (
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func validateReverseAndHints(manifest Manifest, original map[string]any, mapped mappingResult) ([]ReverseResult, []EmittedEntityHint, error) {
	ocsf, err := decodeOutput(mapped.OCSF)
	if err != nil {
		return nil, nil, err
	}
	ecs, err := decodeOutput(mapped.ECS)
	if err != nil {
		return nil, nil, err
	}
	applied := stringSet(mapped.AppliedRules)
	reverse := make([]ReverseResult, 0, len(mapped.AppliedRules))
	hints := make([]EmittedEntityHint, 0)
	for _, rule := range manifest.Rules {
		if _, exists := applied[rule.RuleID]; !exists || rule.InputPath == nil {
			continue
		}
		input, present, err := selectInput(original, *rule.InputPath)
		if err != nil || !present {
			return nil, nil, newError(InvalidInput, ReverseValidationFailed, err)
		}
		target := ocsf
		if rule.OutputNamespace == "ecs" {
			target = ecs
		}
		output, present, err := selectInput(target, rule.OutputPath)
		if err != nil || !present {
			return nil, nil, newError(InvalidInput, ReverseValidationFailed, err)
		}
		if rule.Reversibility == "reversible" {
			if !reverseMatches(rule, input, output) {
				return nil, nil, newError(DeniedError, ReverseValidationFailed, nil)
			}
			reverse = append(reverse, ReverseResult{RuleID: rule.RuleID,
				SourcePathDigest: digestBytes([]byte(*rule.InputPath)), OutputPathDigest: digestBytes([]byte(rule.OutputPath)), Result: "passed"})
		}
		if rule.EntityHint != nil {
			key, err := scalarKey(input)
			if err != nil {
				return nil, nil, newError(InvalidInput, ReverseValidationFailed, err)
			}
			hints = append(hints, EmittedEntityHint{RuleID: rule.RuleID, OutputPath: rule.OutputPath,
				SourceFieldDigest: digestBytes([]byte(key)), Role: rule.EntityHint.Role,
				IdentifierType: rule.EntityHint.IdentifierType, Normalization: rule.EntityHint.Normalization,
				ConfidenceCeilingMillionths: rule.EntityHint.ConfidenceCeilingMillionths})
		}
	}
	return reverse, hints, nil
}

func decodeOutput(raw json.RawMessage) (map[string]any, error) {
	value, err := domaincontract.DecodeUnique(raw)
	if err != nil {
		return nil, newError(InvalidInput, ReverseValidationFailed, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, newError(InvalidInput, ReverseValidationFailed, nil)
	}
	return object, nil
}

func reverseMatches(rule Rule, input, output any) bool {
	inputKey, inputErr := scalarKey(input)
	outputKey, outputErr := scalarKey(output)
	if inputErr != nil || outputErr != nil {
		return false
	}
	switch rule.Operation {
	case Copy, TimestampReference:
		return inputKey == outputKey
	case Enum:
		for _, entry := range rule.EnumTable {
			source, sourceErr := decodeScalar(entry.Source)
			target, targetErr := decodeScalar(entry.Target)
			sourceKey, sourceKeyErr := scalarKey(source)
			targetKey, targetKeyErr := scalarKey(target)
			if sourceErr == nil && targetErr == nil && sourceKeyErr == nil && targetKeyErr == nil &&
				sourceKey == inputKey && targetKey == outputKey {
				return true
			}
		}
		return false
	case ToInteger:
		value, ok := input.(string)
		number, numberOK := output.(json.Number)
		return ok && numberOK && value == number.String()
	case ToString:
		value, ok := output.(string)
		if !ok {
			return false
		}
		reversed, err := convertString(input)
		return err == nil && reversed == value
	default:
		return false
	}
}
