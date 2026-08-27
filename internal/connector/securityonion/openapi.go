package securityonion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type openAPIDocument struct {
	OpenAPI    string                 `json:"openapi"`
	Paths      map[string]openAPIPath `json:"paths"`
	Components openAPIComponents      `json:"components"`
}

type openAPIComponents struct {
	SecuritySchemes map[string]openAPISecurity `json:"securitySchemes"`
}

type openAPISecurity struct {
	Type   string `json:"type"`
	Scheme string `json:"scheme"`
}

type openAPIPath struct {
	Get *openAPIOperation `json:"get"`
}

type openAPIOperation struct {
	Parameters []openAPIParameter           `json:"parameters"`
	Responses  map[string]openAPIResponse   `json:"responses"`
	Security   []map[string]json.RawMessage `json:"security"`
}

type openAPIParameter struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Schema   struct {
		Type string `json:"type"`
	} `json:"schema"`
}

type openAPIResponse struct {
	Content map[string]openAPIMedia `json:"content"`
}

type openAPIMedia struct {
	Schema struct {
		Type string `json:"type"`
	} `json:"schema"`
}

func (qualifier *Qualifier) qualify(ctx context.Context, document []byte) (ValidatedQualification, error) {
	if qualifier == nil {
		return ValidatedQualification{}, invalid("securityonion_qualifier_required")
	}
	if err := ctx.Err(); err != nil {
		return ValidatedQualification{}, err
	}
	if len(document) == 0 || uint64(len(document)) > qualifier.config.MaximumOpenAPIBytes {
		return ValidatedQualification{}, denied("securityonion_openapi_size_invalid")
	}
	canonical, err := domaincontract.Canonicalize(document)
	if err != nil {
		return ValidatedQualification{}, denied("securityonion_openapi_invalid")
	}
	var value openAPIDocument
	if json.Unmarshal(canonical, &value) != nil || !strings.HasPrefix(value.OpenAPI, "3.") {
		return ValidatedQualification{}, denied("securityonion_openapi_invalid")
	}
	securityName, err := validateBearer(value.Components.SecuritySchemes)
	if err != nil {
		return ValidatedQualification{}, err
	}
	operations := make([]Operation, 0, 2)
	for _, requirement := range requiredOperations() {
		path, ok := value.Paths[requirement.Path]
		if !ok || path.Get == nil || !operationCompatible(*path.Get, securityName, requirement) {
			return ValidatedQualification{}, conflict("securityonion_openapi_operation_drift")
		}
		operations = append(operations, requirement)
	}
	openAPIDigest := hash("COH-SECURITY-ONION-OPENAPI-V1\x00", canonical)
	now := qualifier.clock.Now().UTC()
	validUntil := now.Add(qualifier.config.QualificationLifetime)
	result := Qualification{SourceID: qualifier.config.SourceID, OpenAPIDigest: openAPIDigest,
		OpenAPIVersion: value.OpenAPI, SecurityScheme: securityName, Operations: operations,
		ObservedAt: now.Format(timestampLayout), ValidUntil: validUntil.Format(timestampLayout)}
	encoded, _ := json.Marshal(result)
	result.Digest = hash("COH-SECURITY-ONION-QUALIFICATION-V1\x00", encoded)
	return ValidatedQualification{value: result, digest: result.Digest}, nil
}

func requiredOperations() []Operation {
	return []Operation{
		{Method: "GET", Path: "/connect/events/", RequiredParameters: []string{"eventLimit", "format", "metricLimit", "query", "range", "zone"}, ResponseMediaType: "application/json", ResponseType: "array"},
		{Method: "GET", Path: "/connect/info/", ResponseMediaType: "application/json", ResponseType: "object"},
	}
}

func validateBearer(values map[string]openAPISecurity) (string, error) {
	names := make([]string, 0, len(values))
	for name, value := range values {
		if value.Type == "http" && strings.EqualFold(value.Scheme, "bearer") {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return "", conflict("securityonion_openapi_security_drift")
	}
	return names[0], nil
}

func operationCompatible(value openAPIOperation, securityName string, required Operation) bool {
	parameters := make([]string, 0, len(value.Parameters))
	for _, parameter := range value.Parameters {
		if parameter.In == "query" && parameter.Required && parameter.Schema.Type == parameterType(parameter.Name) {
			parameters = append(parameters, parameter.Name)
		}
	}
	slices.Sort(parameters)
	if !slices.Equal(parameters, required.RequiredParameters) || len(value.Security) != 1 {
		return false
	}
	rawSecurity, ok := value.Security[0][securityName]
	var scopes []string
	if !ok || json.Unmarshal(rawSecurity, &scopes) != nil || len(scopes) != 0 {
		return false
	}
	response, ok := value.Responses["200"]
	if !ok {
		return false
	}
	media, ok := response.Content[required.ResponseMediaType]
	return ok && media.Schema.Type == required.ResponseType
}

func parameterType(name string) string {
	if name == "eventLimit" || name == "metricLimit" {
		return "integer"
	}
	return "string"
}

func hash(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
