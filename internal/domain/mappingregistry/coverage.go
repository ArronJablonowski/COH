package mappingregistry

import (
	"context"
	"encoding/json"
	"sort"
)

func inventoryOriginal(ctx context.Context, original map[string]any, limits Limits) ([]string, error) {
	paths := make([]string, 0, limits.MaxInputLeaves)
	visits := 0
	if err := walkInventory(ctx, original, "original", 0, limits, &visits, &paths); err != nil {
		return nil, err
	}
	if len(paths) == 0 || len(paths) > int(limits.MaxInputLeaves) {
		return nil, newError(InvalidInput, CoverageInvalid, nil)
	}
	sort.Strings(paths)
	return paths, nil
}

func walkInventory(ctx context.Context, value any, path string, depth int, limits Limits, visits *int, paths *[]string) error {
	*visits++
	if *visits%128 == 0 {
		if err := checkContext(ctx); err != nil {
			return err
		}
	}
	if depth > int(limits.MaxDepth) {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	object, isObject := value.(map[string]any)
	if isObject && len(object) > 0 {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := path + "." + key
			if !validPath(child, "original") {
				return newError(InvalidInput, CoverageInvalid, nil)
			}
			if err := walkInventory(ctx, object[key], child, depth+1, limits, visits, paths); err != nil {
				return err
			}
		}
		return nil
	}
	if path == "original" {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > int(limits.MaxValueBytes) {
		return newError(InvalidInput, CoverageInvalid, err)
	}
	*paths = append(*paths, path)
	if len(*paths) > int(limits.MaxInputLeaves) {
		return newError(InvalidInput, CoverageInvalid, nil)
	}
	return nil
}

func classifyCoverage(manifest Manifest, inventory []string, mapped mappingResult) (string, []string, []string, error) {
	mappedSet := stringSet(mapped.MappedPaths)
	ignoredSet := make(map[string]struct{}, len(manifest.IgnoredFields))
	for _, ignored := range manifest.IgnoredFields {
		ignoredSet[ignored.Path] = struct{}{}
	}
	unmapped := append([]string(nil), mapped.MissingPaths...)
	for _, path := range inventory {
		if _, exists := mappedSet[path]; exists {
			continue
		}
		if _, exists := ignoredSet[path]; exists {
			continue
		}
		unmapped = append(unmapped, path)
	}
	unmapped = sortedUnique(unmapped)
	if manifest.UnmappedPolicy == "deny" && len(unmapped) > 0 {
		return "", nil, nil, newError(DeniedError, UnmappedFieldDenied, nil)
	}
	partial := sortedUnique(append(append([]string(nil), unmapped...), mapped.LossyPaths...))
	coverage := "complete"
	if len(partial) > 0 {
		coverage = "partial"
		if len(mapped.MappedPaths) == 0 {
			coverage = "unmapped"
		}
	}
	return coverage, unmapped, vendorPaths(partial), nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
