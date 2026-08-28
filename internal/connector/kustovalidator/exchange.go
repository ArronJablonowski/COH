package kustovalidator

import "strings"

// ValidateHelperExchange binds a strictly decoded response to the exact helper
// request. It is required even when both documents are independently valid.
func ValidateHelperExchange(request HelperRequest, response HelperResponse) error {
	if validateHelperRequest(request) != nil || validateHelperResponse(response) != nil ||
		response.RequestID != request.RequestID || response.RequestDigest != request.RequestDigest ||
		response.SchemaDigest != request.SchemaDigest || response.RegistryDigest != request.Policy.RegistryDigest ||
		response.HelperIdentity != request.HelperIdentityExpectation ||
		(response.Outcome == "accepted" && response.TerminalTake > request.RequestedRows) {
		return denied()
	}
	if response.Outcome == "accepted" && validateSemanticAgainstSchema(request.Schema, response.Semantic) != nil {
		return denied()
	}
	return nil
}

func validateSemanticAgainstSchema(schema SchemaBinding, semantic SemanticInventory) error {
	tables := make(map[string]map[string]struct{}, len(schema.Tables))
	for _, table := range schema.Tables {
		columns := make(map[string]struct{}, len(table.Columns))
		for _, column := range table.Columns {
			columns[column.Name] = struct{}{}
		}
		tables[table.Name] = columns
	}
	for _, table := range semantic.Tables {
		if _, present := tables[table]; !present {
			return denied()
		}
	}
	for _, path := range semantic.Columns {
		parts := strings.SplitN(path, ".", 2)
		columns, tablePresent := tables[parts[0]]
		_, columnPresent := columns[parts[1]]
		if !tablePresent || !columnPresent {
			return denied()
		}
	}
	return nil
}
