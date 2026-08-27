package splunkparser

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var (
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	vendorPattern = regexp.MustCompile(`^_?[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	indexPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	testPattern   = regexp.MustCompile(`^Test[A-Za-z0-9]{3,127}$`)
)

var allowedCommands = []string{"fields", "head", "search", "sort", "stats", "table"}

var prohibitedCommands = []CommandRule{
	{Name: "append", Class: "alternate_execution"},
	{Name: "appendcols", Class: "alternate_execution"},
	{Name: "appendlookup", Class: "dynamic_lookup"},
	{Name: "appendpipe", Class: "alternate_execution"},
	{Name: "collect", Class: "external_effect"},
	{Name: "datamodel", Class: "alternate_source"},
	{Name: "delete", Class: "external_effect"},
	{Name: "dump", Class: "external_effect"},
	{Name: "foreach", Class: "dynamic_execution"},
	{Name: "from", Class: "alternate_source"},
	{Name: "inputcsv", Class: "alternate_source"},
	{Name: "inputlookup", Class: "dynamic_lookup"},
	{Name: "join", Class: "alternate_execution"},
	{Name: "loadjob", Class: "saved_state"},
	{Name: "localop", Class: "execution_control"},
	{Name: "lookup", Class: "dynamic_lookup"},
	{Name: "makeresults", Class: "alternate_source"},
	{Name: "map", Class: "dynamic_execution"},
	{Name: "mcollect", Class: "external_effect"},
	{Name: "metadata", Class: "alternate_source"},
	{Name: "metasearch", Class: "alternate_source"},
	{Name: "meventcollect", Class: "external_effect"},
	{Name: "multisearch", Class: "alternate_execution"},
	{Name: "outputcsv", Class: "external_effect"},
	{Name: "outputlookup", Class: "external_effect"},
	{Name: "pivot", Class: "alternate_source"},
	{Name: "rest", Class: "dynamic_execution"},
	{Name: "run", Class: "external_effect"},
	{Name: "runshellscript", Class: "external_effect"},
	{Name: "savedsearch", Class: "saved_state"},
	{Name: "script", Class: "external_effect"},
	{Name: "sendalert", Class: "external_effect"},
	{Name: "sendemail", Class: "external_effect"},
	{Name: "tstats", Class: "alternate_source"},
	{Name: "tscollect", Class: "external_effect"},
	{Name: "union", Class: "alternate_execution"},
}

func DecodeDefinition(input []byte) (Definition, error) {
	var value Definition
	if err := decodeExact(input, &value); err != nil {
		return Definition{}, err
	}
	if err := validateDefinition(value); err != nil {
		return Definition{}, err
	}
	return value, nil
}

func DecodePlan(input []byte) (Plan, error) {
	var value Plan
	if err := decodeExact(input, &value); err != nil {
		return Plan{}, err
	}
	if err := validatePlan(value); err != nil {
		return Plan{}, err
	}
	return value, nil
}

func DecodePolicyDecision(input []byte) (PolicyDecision, error) {
	var value PolicyDecision
	if err := decodeExact(input, &value); err != nil {
		return PolicyDecision{}, err
	}
	if err := validateDecision(value); err != nil {
		return PolicyDecision{}, err
	}
	return value, nil
}

func DecodeCommandRegistry(input []byte) (CommandRegistry, error) {
	var value CommandRegistry
	if err := decodeExact(input, &value); err != nil {
		return CommandRegistry{}, err
	}
	if value.SchemaVersion != RegistryVersion || value.ContractVersion != ContractVersion ||
		value.RegistryVersion != ValidatorVersion || !slices.Equal(value.AllowedCommands, allowedCommands) ||
		!slices.Equal(value.ProhibitedCommands, prohibitedCommands) || value.BackticksAllowed || value.MacrosAllowed ||
		value.LookupsAllowed || value.CustomAllowed || value.Digest != registryDigest(value) {
		return CommandRegistry{}, denied("command registry invalid")
	}
	return value, nil
}

func DecodeDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if err := decodeExact(input, &value); err != nil {
		return DenialCorpus{}, err
	}
	if value.SchemaVersion != DenialCorpusVersion || value.ContractVersion != ContractVersion ||
		len(value.Cases) < 24 || len(value.Cases) > 128 {
		return DenialCorpus{}, denied("denial corpus invalid")
	}
	seen := map[string]struct{}{}
	for _, item := range value.Cases {
		key := item.Class + "\x00" + item.Input
		if !namePattern.MatchString(item.Class) || len(item.Input) == 0 || len(item.Input) > 4096 ||
			strings.ContainsAny(item.Input, "\x00\r\n") || !reasonPattern.MatchString(item.Reason) ||
			!testPattern.MatchString(item.CoveredBy) {
			return DenialCorpus{}, denied("denial case invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return DenialCorpus{}, denied("denial case duplicate")
		}
		seen[key] = struct{}{}
	}
	return value, nil
}

func DecodeRedactedAudit(input []byte) (RedactedAudit, error) {
	var value RedactedAudit
	if err := decodeExact(input, &value); err != nil {
		return RedactedAudit{}, err
	}
	if value.SchemaVersion != RedactedAuditVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.Event) || !oneOf(value.Outcome, "accepted", "denied", "revoked") ||
		!validReasons(value.ReasonCodes) || !uuidPattern.MatchString(value.QueryID) || !uuidPattern.MatchString(value.ActorID) ||
		!validDigests(value.ScopeDigest, value.QueryDigest, value.PlanDigest, value.RegistryDigest,
			value.ParserReceiptDigest, value.PolicyDecisionDigest, value.AuditReservationDigest) ||
		value.NativeTextExposed || value.LiteralExposed || value.CredentialExposed || value.VendorBodyExposed || value.SIDExposed {
		return RedactedAudit{}, denied("redacted audit invalid")
	}
	return value, nil
}

func DecodeRevocationEvidence(input []byte) (RevocationEvidence, error) {
	var value RevocationEvidence
	if err := decodeExact(input, &value); err != nil {
		return RevocationEvidence{}, err
	}
	if value.SchemaVersion != RevocationVersion || value.ContractVersion != ContractVersion ||
		!validDigests(value.DecisionDigest, value.RevocationDigest, value.AuditReservationDigest) ||
		!reasonPattern.MatchString(value.ReasonCode) || !validTimestamp(value.ObservedAt) || value.ExecutionPermitted {
		return RevocationEvidence{}, denied("revocation evidence invalid")
	}
	return value, nil
}

func validateDefinition(value Definition) error {
	if value.SchemaVersion != DefinitionVersion || value.ContractVersion != ContractVersion ||
		value.ValidatorVersion != ValidatorVersion || !namePattern.MatchString(value.SourceID) ||
		len(value.Resources) == 0 || len(value.Resources) > 256 || len(value.Fields) == 0 || len(value.Fields) > 4096 ||
		!validNames(value.DefaultProjection, 1, MaximumProjection) || len(value.StableSort) == 0 ||
		len(value.StableSort) > MaximumSortFields || !namePattern.MatchString(value.TimestampField) ||
		!validOptionalName(value.TenantField) || !validOptionalName(value.SourceField) ||
		value.HardMaximumRows == 0 || value.HardMaximumRows > 100000 {
		return denied("definition invalid")
	}
	resources := map[string]struct{}{}
	previous := ""
	for _, resource := range value.Resources {
		if !namePattern.MatchString(resource.ID) || !safeIndex(resource.VendorIndex) || resource.ID <= previous {
			return denied("definition resource invalid")
		}
		resources[resource.ID], previous = struct{}{}, resource.ID
	}
	fields := map[string]FieldRule{}
	previous = ""
	for _, field := range value.Fields {
		if !namePattern.MatchString(field.Name) || !vendorPattern.MatchString(field.VendorName) || field.Name <= previous ||
			!oneOf(field.Type, "string", "integer", "boolean", "timestamp", "ip", "bytes") ||
			(!field.Projectable && !field.Filterable && !field.Sortable && !field.Aggregatable) {
			return denied("definition field invalid")
		}
		fields[field.Name], previous = field, field.Name
	}
	for _, name := range value.DefaultProjection {
		if field, ok := fields[name]; !ok || !field.Projectable {
			return denied("definition projection invalid")
		}
	}
	seenSort := map[string]struct{}{}
	for _, sort := range value.StableSort {
		field, ok := fields[sort.Name]
		if !ok || !field.Sortable || !oneOf(sort.Direction, "asc", "desc") {
			return denied("definition sort invalid")
		}
		if _, duplicate := seenSort[sort.Name]; duplicate {
			return denied("definition sort duplicate")
		}
		seenSort[sort.Name] = struct{}{}
		if !slices.Contains(value.DefaultProjection, sort.Name) {
			return denied("definition stable sort projection invalid")
		}
	}
	for index, required := range []string{value.TimestampField, value.TenantField, value.SourceField} {
		if required != "" {
			field, ok := fields[required]
			if !ok || index == 0 && field.Type != "timestamp" || index > 0 && !field.Filterable {
				return denied("definition mandatory field invalid")
			}
		}
	}
	return nil
}

func validatePlan(value Plan) error {
	earliest, earliestErr := time.Parse("2006-01-02T15:04:05.000000000Z", value.Earliest)
	latest, latestErr := time.Parse("2006-01-02T15:04:05.000000000Z", value.Latest)
	if value.SchemaVersion != PlanVersion || value.ContractVersion != ContractVersion ||
		value.ValidatorVersion != ValidatorVersion || !uuidPattern.MatchString(value.QueryID) ||
		!namePattern.MatchString(value.SourceID) || !validNames(value.ResourceIDs, 1, 256) ||
		len(value.CanonicalSPL) == 0 || len(value.CanonicalSPL) > MaximumInputBytes ||
		strings.ContainsAny(value.CanonicalSPL, "`\x00\r\n") || len(value.Columns) == 0 || len(value.Columns) > MaximumProjection ||
		len(value.Aggregations) > MaximumAggregations || len(value.Sort) > MaximumSortFields ||
		earliestErr != nil || latestErr != nil || !earliest.Before(latest) ||
		value.MaximumRows == 0 || value.MaximumRows > 100000 || value.MaximumBytes == 0 || value.MaximumBytes > MaximumDocumentBytes ||
		value.MaximumDurationMillis == 0 || value.MaximumDurationMillis > 120000 ||
		value.SubsearchCount > MaximumSubsearches || value.CommandCount == 0 || value.CommandCount > MaximumCommands*(value.SubsearchCount+1) ||
		!validDigests(value.QueryDigest, value.CapabilityDigest, value.SchemaDigest, value.Authority.AuthorizationDigest,
			value.Authority.PolicyDecisionDigest, value.Authority.AuditReservationDigest, value.RegistryDigest,
			value.MandatoryFilterDigest, value.PlanDigest) || !uuidPattern.MatchString(value.Authority.ActorID) || value.PlanDigest != planDigest(value) {
		return denied("plan invalid")
	}
	columnNames := map[string]struct{}{}
	for _, column := range value.Columns {
		if !namePattern.MatchString(column.LogicalName) || !vendorPattern.MatchString(column.VendorName) ||
			!oneOf(column.Type, "string", "integer", "boolean", "timestamp", "ip", "bytes") {
			return denied("plan column invalid")
		}
		if _, duplicate := columnNames[column.LogicalName]; duplicate {
			return denied("plan column duplicate")
		}
		columnNames[column.LogicalName] = struct{}{}
	}
	for _, aggregation := range value.Aggregations {
		if !oneOf(aggregation.Function, "avg", "count", "dc", "max", "min", "sum") ||
			(aggregation.Function != "count" && (!namePattern.MatchString(aggregation.InputLogical) || !vendorPattern.MatchString(aggregation.InputVendor))) ||
			!namePattern.MatchString(aggregation.OutputName) || !oneOf(aggregation.OutputType, "string", "integer", "boolean", "timestamp", "ip", "bytes") {
			return denied("plan aggregation invalid")
		}
	}
	for _, sort := range value.Sort {
		if !namePattern.MatchString(sort.Name) || !oneOf(sort.Direction, "asc", "desc") {
			return denied("plan sort invalid")
		}
	}
	return nil
}

func validateDecision(value PolicyDecision) error {
	observed, observedErr := time.Parse(time.RFC3339Nano, value.ObservedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, value.ValidUntil)
	if value.SchemaVersion != DecisionVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) || !uuidPattern.MatchString(value.QueryID) ||
		!oneOf(value.Outcome, "accepted", "denied") || !validReasons(value.ReasonCodes) ||
		(value.Outcome == "accepted" && len(value.ReasonCodes) != 0) || (value.Outcome == "denied" && len(value.ReasonCodes) == 0) ||
		value.ValidatorVersion != ValidatorVersion || !uuidPattern.MatchString(value.ActorID) ||
		!validDigests(value.ScopeDigest, value.QueryDigest, value.CapabilityDigest, value.SchemaDigest, value.PlanDigest,
			value.RegistryDigest, value.ParserReceiptDigest, value.PolicyDecisionDigest, value.AuditReservationDigest, value.Digest) ||
		observedErr != nil || validErr != nil || !observed.Before(validUntil) || value.Digest != decisionDigest(value) {
		return denied("policy decision invalid")
	}
	return nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > MaximumDocumentBytes {
		return denied("document size invalid")
	}
	unique, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return denied("document JSON invalid")
	}
	encoded, err := json.Marshal(unique)
	if err != nil {
		return denied("document JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return denied("document shape invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return denied("document trailing data")
	}
	return nil
}

func RegistryDigest(value CommandRegistry) string { return registryDigest(value) }
func DecisionDigest(value PolicyDecision) string  { return decisionDigest(value) }
func PlanDigest(value Plan) string                { return planDigest(value) }

func registryDigest(value CommandRegistry) string {
	value.Digest = ""
	return hash("COH-SPLUNK-COMMAND-REGISTRY-V1\x00", value)
}

func decisionDigest(value PolicyDecision) string {
	value.Digest = ""
	return hash("COH-SPLUNK-PARSER-DECISION-V1\x00", value)
}

func planDigest(value Plan) string {
	value.PlanDigest = ""
	return hash("COH-SPLUNK-PLAN-V1\x00", value)
}

func hash(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func safeIndex(value string) bool {
	return indexPattern.MatchString(value) && !strings.HasPrefix(value, "_") && !strings.ContainsAny(value, "*,:/%\\") && value != "all"
}

func validNames(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !namePattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validReasons(values []string) bool {
	if len(values) > 64 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !reasonPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validOptionalName(value string) bool { return value == "" || namePattern.MatchString(value) }

func validTimestamp(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == value
}

func oneOf[T comparable](value T, options ...T) bool { return slices.Contains(options, value) }
func denied(reason string) error                     { return fmt.Errorf("splunk parser contract denied: %s", reason) }
