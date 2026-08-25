package domaincontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalidSchema = errors.New("invalid domain schema")

type schemaDocument struct {
	definitions map[string]any
}

type schemaTarget struct {
	document *schemaDocument
	name     string
	boundary string
}

// Validator evaluates the deliberately bounded JSON Schema vocabulary used by
// the versioned domain contracts. It is immutable after loading.
type Validator struct {
	kinds    map[string]schemaTarget
	patterns map[string]*regexp.Regexp
}

// LoadValidator loads the registry and every referenced payload schema from
// root. Unknown keywords are rejected so unsupported semantics cannot be
// silently ignored.
func LoadValidator(root fs.FS) (*Validator, error) {
	registryValue, err := readUniqueFile(root, "contract-registry.json")
	if err != nil {
		return nil, err
	}
	registry, ok := registryValue.(map[string]any)
	if !ok || registry["schema"] != "coh.domain.registry/v1" || registry["contract_schema"] != "coh.domain/v1" {
		return nil, schemaError("registry identity")
	}
	registered, err := stringSet(registry["kinds"])
	if err != nil {
		return nil, schemaError("registry kinds")
	}
	references, ok := registry["implemented_kind_schemas"].(map[string]any)
	if !ok || len(references) != len(registered) {
		return nil, schemaError("registry implementation map")
	}
	boundaries, ok := registry["case_boundaries"].(map[string]any)
	if !ok || len(boundaries) != len(registered) {
		return nil, schemaError("registry case-boundary map")
	}
	validator := &Validator{patterns: make(map[string]*regexp.Regexp), kinds: make(map[string]schemaTarget)}
	documents := make(map[string]*schemaDocument)
	for kind := range registered {
		boundary, ok := boundaries[kind].(string)
		if !ok || boundary != "required" && boundary != "optional" && boundary != "self" {
			return nil, schemaError("invalid case boundary for %s", kind)
		}
		reference, ok := references[kind].(string)
		if !ok {
			return nil, schemaError("missing schema for %s", kind)
		}
		filename, name, ok := strings.Cut(reference, "#/$defs/")
		if !ok || filename == "" || name == "" || path.Base(filename) != filename {
			return nil, schemaError("unsafe schema reference for %s", kind)
		}
		document := documents[filename]
		if document == nil {
			document, err = validator.loadDocument(root, filename)
			if err != nil {
				return nil, err
			}
			documents[filename] = document
		}
		if _, exists := document.definitions[name]; !exists || name != kind {
			return nil, schemaError("schema target mismatch for %s", kind)
		}
		validator.kinds[kind] = schemaTarget{document: document, name: name, boundary: boundary}
	}
	return validator, nil
}

func (validator *Validator) loadDocument(root fs.FS, filename string) (*schemaDocument, error) {
	value, err := readUniqueFile(root, filename)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || object["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		return nil, schemaError("document identity: %s", filename)
	}
	if err := exactKeywords(object, "$schema", "$id", "title", "$defs"); err != nil {
		return nil, err
	}
	definitions, ok := object["$defs"].(map[string]any)
	if !ok || len(definitions) == 0 {
		return nil, schemaError("definitions: %s", filename)
	}
	document := &schemaDocument{definitions: definitions}
	for name, definition := range definitions {
		if err := validator.checkNode(document, definition, 0); err != nil {
			return nil, schemaError("%s definition %s: %v", filename, name, err)
		}
	}
	return document, nil
}

func (validator *Validator) checkNode(document *schemaDocument, value any, depth int) error {
	if depth > 64 {
		return schemaError("schema nesting exceeds 64")
	}
	node, ok := value.(map[string]any)
	if !ok {
		return schemaError("schema node must be an object")
	}
	if err := exactKeywords(node, "$ref", "type", "required", "properties", "additionalProperties", "enum", "pattern", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "items", "oneOf"); err != nil {
		return err
	}
	if reference, exists := node["$ref"]; exists {
		text, ok := reference.(string)
		name := strings.TrimPrefix(text, "#/$defs/")
		if !ok || name == text || name == "" || len(node) != 1 {
			return schemaError("only local definition references are allowed")
		}
		if _, exists := document.definitions[name]; !exists {
			return schemaError("unresolved definition reference")
		}
		return nil
	}
	if rawType, exists := node["type"]; exists {
		typeName, ok := rawType.(string)
		if !ok || !supportedType(typeName) {
			return schemaError("unsupported type")
		}
	}
	properties, _ := node["properties"].(map[string]any)
	if required, exists := node["required"]; exists {
		names, err := stringSet(required)
		if err != nil {
			return schemaError("required must contain unique strings")
		}
		for name := range names {
			if _, exists := properties[name]; !exists {
				return schemaError("required property %s is undefined", name)
			}
		}
	}
	if additional, exists := node["additionalProperties"]; exists {
		if _, ok := additional.(bool); !ok {
			return schemaError("additionalProperties must be boolean")
		}
	}
	if rawEnum, exists := node["enum"]; exists {
		if _, err := stringSet(rawEnum); err != nil {
			return schemaError("enum must contain unique strings")
		}
	}
	for _, keyword := range []string{"minimum", "maximum"} {
		if value, exists := node[keyword]; exists {
			if _, ok := schemaNumber(value); !ok {
				return schemaError("%s must be a number", keyword)
			}
		}
	}
	for _, keyword := range []string{"minLength", "maxLength", "minItems", "maxItems"} {
		if value, exists := node[keyword]; exists && !schemaNonnegativeInteger(value) {
			return schemaError("%s must be a nonnegative int64", keyword)
		}
	}
	if pattern, exists := node["pattern"]; exists {
		text, ok := pattern.(string)
		if !ok {
			return schemaError("pattern must be a string")
		}
		compiled, err := regexp.Compile(text)
		if err != nil {
			return schemaError("invalid pattern")
		}
		validator.patterns[text] = compiled
	}
	for _, keyword := range []string{"properties"} {
		if children, exists := node[keyword]; exists {
			object, ok := children.(map[string]any)
			if !ok {
				return schemaError("%s must be an object", keyword)
			}
			for _, child := range object {
				if err := validator.checkNode(document, child, depth+1); err != nil {
					return err
				}
			}
		}
	}
	for _, keyword := range []string{"items"} {
		if child, exists := node[keyword]; exists {
			if err := validator.checkNode(document, child, depth+1); err != nil {
				return err
			}
		}
	}
	if choices, exists := node["oneOf"]; exists {
		array, ok := choices.([]any)
		if !ok || len(array) < 2 {
			return schemaError("oneOf must contain choices")
		}
		for _, child := range array {
			if err := validator.checkNode(document, child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func supportedType(value string) bool {
	switch value {
	case "array", "boolean", "integer", "null", "object", "string":
		return true
	default:
		return false
	}
}

func schemaNonnegativeInteger(value any) bool {
	number, ok := value.(json.Number)
	if !ok || !canonicalInteger(number.String()) || strings.HasPrefix(number.String(), "-") {
		return false
	}
	_, err := strconv.ParseInt(number.String(), 10, 64)
	return err == nil
}

func schemaNumber(value any) (*big.Rat, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, false
	}
	result, ok := new(big.Rat).SetString(number.String())
	return result, ok
}

func readUniqueFile(root fs.FS, name string) (any, error) {
	input, err := fs.ReadFile(root, name)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrInvalidSchema, name, err)
	}
	value, err := DecodeUnique(input)
	if err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", ErrInvalidSchema, name, err)
	}
	return value, nil
}

func stringSet(value any) (map[string]struct{}, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, ErrInvalidSchema
	}
	result := make(map[string]struct{}, len(array))
	for _, item := range array {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, ErrInvalidSchema
		}
		result[text] = struct{}{}
	}
	if len(result) != len(array) {
		return nil, ErrInvalidSchema
	}
	return result, nil
}

func exactKeywords(object map[string]any, allowed ...string) error {
	sort.Strings(allowed)
	for keyword := range object {
		index := sort.SearchStrings(allowed, keyword)
		if index == len(allowed) || allowed[index] != keyword {
			return schemaError("unsupported keyword %s", keyword)
		}
	}
	return nil
}

func schemaError(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSchema, fmt.Sprintf(format, values...))
}
