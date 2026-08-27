package mappingregistry

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

type mappingResult struct {
	OCSF         json.RawMessage
	ECS          json.RawMessage
	AppliedRules []string
	MappedPaths  []string
	MissingPaths []string
	LossyPaths   []string
}

func executeMapping(ctx context.Context, manifest Manifest, original map[string]any) (mappingResult, error) {
	if original == nil {
		return mappingResult{}, newError(InvalidInput, TypeMismatch, nil)
	}
	if err := validateManifest(ctx, manifest); err != nil {
		return mappingResult{}, err
	}
	ocsf, ecs := make(map[string]any), make(map[string]any)
	result := mappingResult{}
	for index, rule := range manifest.Rules {
		if index%64 == 0 {
			if err := checkContext(ctx); err != nil {
				return mappingResult{}, err
			}
		}
		input, present, err := ruleInput(original, rule, manifest.Limits.MaxValueBytes)
		if err != nil {
			return mappingResult{}, err
		}
		if !present {
			result.MissingPaths = append(result.MissingPaths, *rule.InputPath)
			continue
		}
		output, err := applyOperation(rule, input, manifest.Limits.MaxValueBytes)
		if err != nil {
			return mappingResult{}, err
		}
		target := ocsf
		if rule.OutputNamespace == "ecs" {
			target = ecs
		}
		if err := setOutput(target, rule.OutputPath, output); err != nil {
			return mappingResult{}, err
		}
		result.AppliedRules = append(result.AppliedRules, rule.RuleID)
		if rule.InputPath != nil {
			result.MappedPaths = append(result.MappedPaths, *rule.InputPath)
			if rule.LossState == "lossy" {
				result.LossyPaths = append(result.LossyPaths, *rule.InputPath)
			}
		}
	}
	if err := checkContext(ctx); err != nil {
		return mappingResult{}, err
	}
	result.MappedPaths = sortedUnique(result.MappedPaths)
	result.MissingPaths = sortedUnique(result.MissingPaths)
	result.LossyPaths = sortedUnique(result.LossyPaths)
	ocsfBytes, _, err := canonicalValue(ocsf)
	if err != nil {
		return mappingResult{}, err
	}
	ecsBytes, _, err := canonicalValue(ecs)
	if err != nil {
		return mappingResult{}, err
	}
	result.OCSF = json.RawMessage(ocsfBytes)
	result.ECS = json.RawMessage(ecsBytes)
	return result, nil
}

func ruleInput(original map[string]any, rule Rule, maxValueBytes uint32) (any, bool, error) {
	if rule.Operation == Constant {
		return nil, true, nil
	}
	value, present, err := selectInput(original, *rule.InputPath)
	if err != nil {
		return nil, false, err
	}
	if !present {
		if rule.Required {
			return nil, false, newError(InvalidInput, TypeMismatch, nil)
		}
		return nil, false, nil
	}
	if !runtimeType(value, rule.InputType) {
		return nil, false, newError(InvalidInput, TypeMismatch, nil)
	}
	key, err := scalarKey(value)
	if err != nil || len(key) > int(maxValueBytes) {
		return nil, false, newError(InvalidInput, TypeMismatch, err)
	}
	return value, true, nil
}

func selectInput(original map[string]any, path string) (any, bool, error) {
	parts := strings.Split(path, ".")
	var current any = original
	for _, part := range parts[1:] {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false, newError(InvalidInput, TypeMismatch, nil)
		}
		current, ok = object[part]
		if !ok {
			return nil, false, nil
		}
	}
	return current, true, nil
}

func setOutput(target map[string]any, path string, value any) error {
	parts := strings.Split(path, ".")[1:]
	current := target
	for index, part := range parts {
		if index == len(parts)-1 {
			if _, exists := current[part]; exists {
				return newError(ConflictError, OutputCollision, nil)
			}
			current[part] = value
			return nil
		}
		next, exists := current[part]
		if !exists {
			child := make(map[string]any)
			current[part] = child
			current = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return newError(ConflictError, OutputCollision, nil)
		}
		current = child
	}
	return newError(InvalidInput, RuleInvalid, nil)
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
