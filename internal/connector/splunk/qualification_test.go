package splunk

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var splunkTestNow = time.Date(2026, 8, 27, 18, 0, 0, 0, time.UTC)

type splunkFixedClock struct{ now time.Time }

func (clock *splunkFixedClock) Now() time.Time { return clock.now }

type qualificationClientStub struct {
	mu           sync.Mutex
	identity     ServerIdentity
	current      CurrentContext
	indexes      IndexInventory
	fields       RegisteredFieldInventory
	parser       ParserResult
	created      SearchCreateResult
	status       JobStatus
	results      ResultEnvelope
	canceled     SearchCancelResult
	createWait   <-chan struct{}
	receipts     []CallReceipt
	err          error
	operations   []string
	receiptIndex int
}

func (client *qualificationClientStub) ServerInfo(_ context.Context, binding CallBinding) (ServerIdentity, CallReceipt, error) {
	client.operations = append(client.operations, binding.Operation)
	return client.identity, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) CurrentContext(_ context.Context, binding CallBinding) (CurrentContext, CallReceipt, error) {
	client.operations = append(client.operations, binding.Operation)
	return client.current, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) Indexes(_ context.Context, request InventoryRequest) (IndexInventory, CallReceipt, error) {
	client.operations = append(client.operations, request.Binding.Operation)
	return client.indexes, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) RegisteredFields(_ context.Context, request InventoryRequest) (RegisteredFieldInventory, CallReceipt, error) {
	client.operations = append(client.operations, request.Binding.Operation)
	return client.fields, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) ParserPreflight(_ context.Context, request ParserRequest) (ParserResult, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.operations = append(client.operations, request.Binding.Operation)
	return client.parser, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) CreateSearch(_ context.Context, request SearchCreateRequest) (SearchCreateResult, CallReceipt, error) {
	if client.createWait != nil {
		<-client.createWait
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.operations = append(client.operations, request.Binding.Operation)
	return client.created, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) SearchStatus(_ context.Context, request SearchStatusRequest) (JobStatus, CallReceipt, error) {
	client.operations = append(client.operations, request.Binding.Operation)
	return client.status, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) SearchResults(_ context.Context, request SearchResultsRequest) (ResultEnvelope, CallReceipt, error) {
	client.operations = append(client.operations, request.Binding.Operation)
	return client.results, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) CancelSearch(_ context.Context, request SearchCancelRequest) (SearchCancelResult, CallReceipt, error) {
	client.operations = append(client.operations, request.Binding.Operation)
	return client.canceled, client.nextReceipt(), client.err
}

func (client *qualificationClientStub) nextReceipt() CallReceipt {
	if len(client.receipts) == 0 {
		return CallReceipt{}
	}
	index := min(client.receiptIndex, len(client.receipts)-1)
	client.receiptIndex++
	return client.receipts[index]
}

func TestQualifierBindsEnterpriseIdentityCapabilitiesAndReceipts(t *testing.T) {
	qualifier, client := splunkTestQualifier(t)
	qualified, err := qualifier.Qualify(context.Background(), splunkTestBinding("splunk.server_info").Scope,
		splunkTestBinding("splunk.server_info").Authority)
	if err != nil {
		t.Fatal(err)
	}
	value := qualified.Value()
	if value.Digest != qualified.Digest() || value.ProductType != "enterprise" || value.Version != "10.0.0" ||
		!slices.Equal(value.Capabilities, []string{"get_metadata", "search"}) ||
		!slices.Equal(client.operations, []string{"splunk.server_info", "splunk.current_context"}) ||
		len(value.Receipts) != 2 || value.Receipts[0].Operation != "splunk.server_info" ||
		value.Receipts[1].Operation != "splunk.current_context" {
		t.Fatalf("qualification=%+v operations=%v", value, client.operations)
	}
	replayed, err := DecodeValidatedQualification(context.Background(), qualified.CanonicalBytes())
	if err != nil || replayed.Digest() != qualified.Digest() {
		t.Fatalf("replayed=%+v err=%v", replayed.Value(), err)
	}
	mutated := value
	mutated.Build = "substituted"
	encoded, _ := json.Marshal(mutated)
	if _, err := DecodeValidatedQualification(context.Background(), encoded); queryconnector.Reason(err) != "splunk_qualification_digest_invalid" {
		t.Fatalf("mutation err=%v", err)
	}
}

func TestQualifierRejectsIdentityVersionCapabilityAndReceiptDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*qualificationClientStub)
		code   queryconnector.ErrorCode
		reason string
	}{
		{"server guid", func(c *qualificationClientStub) { c.identity.GUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" }, queryconnector.Conflict, "splunk_server_identity_mismatch"},
		{"cloud product", func(c *qualificationClientStub) { c.identity.ProductType = "cloud" }, queryconnector.Conflict, "splunk_server_identity_mismatch"},
		{"server role", func(c *qualificationClientStub) { c.identity.ServerRoles = []string{"indexer"} }, queryconnector.Conflict, "splunk_server_identity_mismatch"},
		{"minor version", func(c *qualificationClientStub) { c.identity.Version = "10.1.0" }, queryconnector.Unsupported, "splunk_version_unqualified"},
		{"missing search", func(c *qualificationClientStub) { c.current.Capabilities = []string{"get_metadata"} }, queryconnector.Denied, "splunk_required_capability_missing"},
		{"dangerous capability", func(c *qualificationClientStub) { c.current.Capabilities = []string{"indexes_edit", "search"} }, queryconnector.Denied, "splunk_dangerous_capability_present"},
		{"transport receipt", func(c *qualificationClientStub) { c.receipts[0].TransportDigest = splunkTestDigest("9") }, queryconnector.Denied, "splunk_qualification_receipt_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			qualifier, client := splunkTestQualifier(t)
			test.mutate(client)
			_, err := qualifier.Qualify(context.Background(), splunkTestBinding("splunk.server_info").Scope,
				splunkTestBinding("splunk.server_info").Authority)
			if queryconnector.Code(err) != test.code || queryconnector.Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", queryconnector.Code(err), queryconnector.Reason(err), err)
			}
		})
	}
}

func TestQualifierRejectsInvalidAuthorityBeforeVendorCalls(t *testing.T) {
	qualifier, client := splunkTestQualifier(t)
	binding := splunkTestBinding("splunk.server_info")
	binding.Authority.PolicyDecisionDigest = "invalid"
	if _, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority); queryconnector.Reason(err) != "splunk_call_binding_invalid" || len(client.operations) != 0 {
		t.Fatalf("err=%v calls=%v", err, client.operations)
	}
}

func TestPublishedQualificationHasVerifiedDigest(t *testing.T) {
	input := mustRead(t, "fixtures/qualification.snapshot.json")
	value, err := DecodeQualification(input)
	if err != nil {
		t.Fatal(err)
	}
	if value.Digest != qualificationDigest(value) {
		t.Fatalf("fixture digest want %s", qualificationDigest(value))
	}
	if _, err := DecodeValidatedQualification(context.Background(), input); err != nil {
		t.Fatal(err)
	}
}

func splunkTestQualifier(t testing.TB) (*Qualifier, *qualificationClientStub) {
	t.Helper()
	config, err := DecodeConfig(mustRead(t.(*testing.T), "fixtures/config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipts := []CallReceipt{
		{RequestDigest: splunkTestDigest("1"), ResponseDigest: splunkTestDigest("2"), LeaseDecisionDigest: splunkTestDigest("3"), TransportDigest: config.TransportIdentityDigest},
		{RequestDigest: splunkTestDigest("4"), ResponseDigest: splunkTestDigest("5"), LeaseDecisionDigest: splunkTestDigest("6"), TransportDigest: config.TransportIdentityDigest},
	}
	client := &qualificationClientStub{identity: ServerIdentity{GUID: config.ExpectedServerGUID,
		ProductType: "enterprise", Version: "10.0.0", Build: "example-build", ServerRoles: []string{"search_head"}},
		current: CurrentContext{Capabilities: []string{"get_metadata", "search"}},
		indexes: IndexInventory{Names: []string{"security"}}, fields: RegisteredFieldInventory{Fields: []RegisteredField{
			{Name: "_time", Indexed: true}, {Name: "src_ip", Indexed: false}}}, receipts: receipts}
	qualifier, err := NewQualifier(config, client, &splunkFixedClock{now: splunkTestNow})
	if err != nil {
		t.Fatal(err)
	}
	return qualifier, client
}
