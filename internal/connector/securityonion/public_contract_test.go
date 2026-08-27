package securityonion

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestPublishedSecurityOnionContractIsSecretFreeAndExact(t *testing.T) {
	root := "../../../contracts/security-onion/v1/"
	capabilityBytes, err := os.ReadFile(root + "fixtures/capability.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	capability, err := queryconnector.DecodeCapability(context.Background(), capabilityBytes)
	value := capability.Value()
	if err != nil || value.SourceID != "security-onion-prod" ||
		!slices.Equal(value.QueryLanguages, []string{"security-onion-oql"}) || !value.Features.ReadOnly ||
		!value.Features.SchemaDiscovery || !value.Features.Validation || !value.Features.Polling ||
		value.Features.Paging || !value.Features.Cancellation || !value.Features.Statistics {
		t.Fatalf("capability=%+v err=%v", value, err)
	}
	for _, name := range []string{"security-onion-config.schema.json", "security-onion-oql.schema.json",
		"fixtures/config.valid.json", "fixtures/denial-corpus.json", "fixtures/redacted-error.trace.json"} {
		input, err := os.ReadFile(root + name)
		if err != nil || !json.Valid(input) {
			t.Fatalf("contract %s invalid: %v", name, err)
		}
		lower := strings.ToLower(string(input))
		for _, forbidden := range []string{`"client_secret"`, `"access_token"`, `"authorization"`, `"vendor_body":`} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("contract %s exposes %s", name, forbidden)
			}
		}
	}
}
