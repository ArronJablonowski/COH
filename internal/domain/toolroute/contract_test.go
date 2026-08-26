package toolroute

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	testOperation = "0198d6c4-1111-7111-8111-111111111111"
	testOrg       = "0198d6c4-2222-7222-8222-222222222222"
	testTenant    = "0198d6c4-3333-7333-8333-333333333333"
	testCase      = "0198d6c4-4444-7444-8444-444444444444"
	testDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestIntentDigestPreservesAgentLoopV1Semantics(t *testing.T) {
	digest, err := Digest(validIntent())
	if err != nil || digest != "sha256:c9d3c223e16e74694ec3742a44a8e23e214aadcd90b65031033a2aa40ed8e715" {
		t.Fatalf("digest=%s err=%v", digest, err)
	}
}

func TestPublishedToolRouteFixturesDecode(t *testing.T) {
	intent, err := os.ReadFile("../../../contracts/tool/v1/fixtures/tool-route-intent.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIntent(intent); err != nil {
		t.Fatalf("intent fixture: %v", err)
	}
	receipt, err := os.ReadFile("../../../contracts/tool/v1/fixtures/tool-route-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReceipt(receipt); err != nil {
		t.Fatalf("receipt fixture: %v", err)
	}
	state, err := os.ReadFile("../../../contracts/tool/v1/fixtures/tool-route-state.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeState(state); err != nil {
		t.Fatalf("state fixture: %v", err)
	}
}

func TestStrictIntentAndReceiptRecordsRoundTrip(t *testing.T) {
	intentRecord := IntentFromDomain(validIntent())
	encoded, err := CanonicalIntent(intentRecord)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeIntent(encoded)
	if err != nil || !reflect.DeepEqual(decoded, intentRecord) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	receipt := domain.ActionReceipt{IntentDigest: testDigest, Outcome: "succeeded",
		Evidence: domain.ArtifactRef{Digest: testDigest, MediaType: "application/json", Classification: "restricted", Length: 12}}
	receiptRecord := ReceiptFromDomain(receipt)
	encodedReceipt, err := CanonicalReceipt(receiptRecord)
	if err != nil {
		t.Fatal(err)
	}
	decodedReceipt, err := DecodeReceipt(encodedReceipt)
	if err != nil || !reflect.DeepEqual(decodedReceipt, receiptRecord) {
		t.Fatalf("decoded=%+v err=%v", decodedReceipt, err)
	}
	for name, malformed := range map[string][]byte{
		"unknown":   append(append([]byte{}, encoded[:len(encoded)-1]...), []byte(`,"extra":true}`)...),
		"duplicate": bytes.Replace(encoded, []byte(`"tool":"query_host"`), []byte(`"tool":"query_host","tool":"query_host"`), 1),
		"missing":   bytes.Replace(encoded, []byte(`"action":"read",`), nil, 1),
		"trailing":  append(append([]byte{}, encoded...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeIntent(malformed); ErrorCode(err) != Denied {
				t.Fatalf("accepted %s: %s err=%v", name, malformed, err)
			}
		})
	}
}

func validIntent() domain.ToolIntent {
	return domain.ToolIntent{OperationID: testOperation,
		Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase},
		Tool: "query_host", Action: "read", TargetDigest: testDigest, ArgumentDigest: testDigest}
}
