package architecturecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var catalogTypes = []string{
	"application_entrypoints", "capability_graph", "configuration",
	"event_routes", "model_surface_events", "module_dependencies",
}

func Generate(ctx context.Context, root, goBinary, declarationPath, outputDir string) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	root = absoluteRoot
	if err := validateSourcePolicy(root); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, declarationPath))
	if err != nil {
		return err
	}
	var declarations Declarations
	if err := decodeStrict(data, &declarations); err != nil {
		return err
	}
	if declarations.SchemaVersion != "coh.architecture-catalog-sources/v1" ||
		declarations.ContractVersion != ContractVersion || len(declarations.Catalogs) != len(catalogTypes) {
		return fmt.Errorf("unsupported or incomplete source declarations")
	}
	packages, err := listPackages(ctx, root, goBinary)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, declaration := range declarations.Catalogs {
		if seen[declaration.CatalogType] || !contains(catalogTypes, declaration.CatalogType) {
			return fmt.Errorf("duplicate or unknown catalog %q", declaration.CatalogType)
		}
		seen[declaration.CatalogType] = true
		catalog, buildErr := build(root, declaration, packages)
		if buildErr != nil {
			return fmt.Errorf("%s: %w", declaration.CatalogType, buildErr)
		}
		encoded, encodeErr := canonical(catalog)
		if encodeErr != nil {
			return encodeErr
		}
		if err := os.WriteFile(filepath.Join(outputDir, declaration.CatalogType+".json"), encoded, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func build(root string, declaration Declaration, packages []goPackage) (Catalog, error) {
	catalog := Catalog{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		CatalogType: declaration.CatalogType, Requirements: append([]string(nil), requirements...)}
	contents := make(map[string][]byte)
	allSources := append([]Source{
		{Path: "contracts/architecture-catalog/v1/architecture-catalog.schema.json", Version: ContractVersion},
		{Path: "contracts/architecture-catalog/v1/source-declarations.json", Version: ContractVersion},
		{Path: "contracts/architecture-catalog/v1/source-declarations.schema.json", Version: ContractVersion},
	}, declaration.Sources...)
	for _, declared := range allSources {
		data, source, err := readSource(root, declared)
		if err != nil {
			return Catalog{}, err
		}
		catalog.Sources = append(catalog.Sources, source)
		contents[source.Path] = data
	}
	var err error
	switch declaration.CatalogType {
	case "capability_graph":
		catalog.Records, err = capabilityRecords(contents["contracts/capability-seam/v1/fixtures/graph.valid.json"])
		if err == nil {
			var authorities []Record
			authorities, err = authorityRecords(contents["internal/domain/capabilityseam/authority_catalog.go"])
			catalog.Records = append(catalog.Records, authorities...)
		}
	case "configuration":
		catalog.Records, err = configurationRecords(contents["contracts/profile-composition/v1/fixtures/layer.signed.valid.json"])
	case "event_routes", "model_surface_events":
		catalog.Records, err = eventRecords(contents["contracts/model-surface/v1/fixtures/event-vocabulary.valid.json"], declaration.CatalogType == "model_surface_events")
	case "module_dependencies":
		catalog.Records = dependencyRecords(packages)
		catalog.Sources, err = appendGoSources(root, catalog.Sources)
	case "application_entrypoints":
		catalog.Records, err = entrypointRecords(root, packages)
		if err == nil {
			catalog.Sources, err = appendGoSources(root, catalog.Sources)
		}
	}
	if err != nil {
		return Catalog{}, err
	}
	for index := range catalog.Records {
		sort.Slice(catalog.Records[index].Attributes, func(a, b int) bool {
			return catalog.Records[index].Attributes[a].Name < catalog.Records[index].Attributes[b].Name
		})
		if unsafeRecord(catalog.Records[index]) {
			return Catalog{}, fmt.Errorf("record %q is unsafe to publish", catalog.Records[index].ID)
		}
	}
	sort.Slice(catalog.Records, func(a, b int) bool {
		return catalog.Records[a].Kind+"\x00"+catalog.Records[a].ID < catalog.Records[b].Kind+"\x00"+catalog.Records[b].ID
	})
	sort.Slice(catalog.Sources, func(a, b int) bool { return catalog.Sources[a].Path < catalog.Sources[b].Path })
	return catalog, nil
}

func listPackages(ctx context.Context, root, goBinary string) ([]goPackage, error) {
	command := exec.CommandContext(ctx, goBinary, "list", "-json", "./...")
	command.Dir = root
	command.Env = append(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var packages []goPackage
	for decoder.More() {
		var value goPackage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		packages = append(packages, value)
	}
	sort.Slice(packages, func(a, b int) bool { return packages[a].ImportPath < packages[b].ImportPath })
	return packages, nil
}

func appendGoSources(root string, sources []Source) ([]Source, error) {
	seen := make(map[string]bool)
	for _, source := range sources {
		seen[source.Path] = true
	}
	paths, err := allGoSourcePaths(root)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		_, source, err := readSource(root, Source{Path: path, Version: "go1.26.7"})
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
		seen[path] = true
	}
	return sources, nil
}

func attr(name, value string) Attribute { return Attribute{Name: name, Value: value} }

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func unsafeRecord(record Record) bool {
	if record.ID == "" || strings.ContainsAny(record.ID, "\r\n\x00") || len(record.ID) > 512 {
		return true
	}
	for _, attribute := range record.Attributes {
		name := strings.ToLower(attribute.Name)
		if strings.ContainsAny(attribute.Value, "\r\n\x00") || len(attribute.Value) > 1024 ||
			contains([]string{"secret", "password", "credential", "token", "prompt", "content", "private_path"}, name) {
			return true
		}
	}
	return false
}
