package workflow

import (
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func TestMemoryMetadataAllowsCaseOptionalScopeWithoutWeakeningOtherKinds(t *testing.T) {
	id := "0198d6c4-5555-7555-8555-555555555555"
	canonical, err := domaincontract.Canonicalize([]byte(`{"schema":"coh.domain/v1","kind":"memory","id":"` + id +
		`","organization_id":"` + testOrg + `","tenant_id":"` + testTenant +
		`","case_id":null,"revision":1,"created_at":"2026-08-26T20:00:00.000000000Z","data":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	record := MetadataRecord{Key: RecordKey{Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant}, Kind: "memory", ID: id},
		Schema: "coh.domain/v1", Revision: 1, Canonical: canonical, Digest: digestBytes(canonical)}
	if err = ValidateMetadataRecord(record); err != nil {
		t.Fatalf("case-optional memory rejected: %v", err)
	}
	record.Key.Kind = "task"
	if err = ValidateMetadataRecord(record); StorageCode(err) != StorageInvalidInput {
		t.Fatalf("case-optional task code=%s err=%v", StorageCode(err), err)
	}
}
