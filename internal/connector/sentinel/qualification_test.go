package sentinel

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var sentinelTestNow = time.Date(2026, 8, 27, 19, 30, 0, 0, time.UTC)

type sentinelFixedClock struct{ now time.Time }

func (clock *sentinelFixedClock) Now() time.Time { return clock.now }

type sentinelQualificationClient struct {
	mu       sync.Mutex
	metadata Metadata
	receipt  CallReceipt
	err      error
	calls    int
	binding  CallBinding
}

func (client *sentinelQualificationClient) Metadata(_ context.Context, request MetadataRequest) (Metadata, CallReceipt, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.calls++
	client.binding = request.Binding
	return client.metadata, client.receipt, client.err
}

func TestQualifierBindsWorkspaceMetadataAuthorityAndExpiry(t *testing.T) {
	qualifier, client, config := sentinelTestQualifier(t)
	binding := sentinelTestBinding(config)
	qualified, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	value := qualified.Value()
	if client.calls != 1 || client.binding.Operation != "sentinel.metadata.get" || client.binding.Audience != TokenAudience ||
		client.binding.TenantID != config.TenantID || value.Digest != qualified.Digest() ||
		value.MetadataDigest != client.metadata.Digest || value.WorkspaceResourceID != config.WorkspaceResourceID ||
		value.ValidUntil != sentinelTestNow.Add(10*time.Minute).Format(sentinelTimestampLayout) || len(value.Receipts) != 1 {
		t.Fatalf("qualification=%+v binding=%+v calls=%d", value, client.binding, client.calls)
	}
	replayed, err := DecodeValidatedQualification(context.Background(), qualified.CanonicalBytes())
	if err != nil || replayed.Digest() != qualified.Digest() {
		t.Fatalf("replayed=%+v err=%v", replayed.Value(), err)
	}
	copyValue := qualified.Value()
	copyValue.Receipts[0].RequestDigest = sentinelTestDigest("9")
	if qualified.Value().Receipts[0].RequestDigest == copyValue.Receipts[0].RequestDigest {
		t.Fatal("qualification exposed mutable receipt state")
	}
}

func TestQualifierRejectsAuthorityBeforeVendorCall(t *testing.T) {
	qualifier, client, config := sentinelTestQualifier(t)
	binding := sentinelTestBinding(config)
	binding.Authority.PolicyDecisionDigest = "invalid"
	if _, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority); queryconnector.Reason(err) != "sentinel_authority_invalid" || client.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, client.calls)
	}
}

func TestQualifierRejectsReceiptIdentityAndSchemaDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sentinelQualificationClient, *sentinelFixedClock)
		code   queryconnector.ErrorCode
		reason string
	}{
		{"receipt", func(client *sentinelQualificationClient, _ *sentinelFixedClock) {
			client.receipt.TransportDigest = sentinelTestDigest("9")
		}, queryconnector.Denied, "sentinel_qualification_receipt_invalid"},
		{"workspace", func(client *sentinelQualificationClient, _ *sentinelFixedClock) {
			client.metadata.WorkspaceID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
			client.metadata.Digest = metadataDigest(client.metadata)
		}, queryconnector.Conflict, "sentinel_workspace_identity_mismatch"},
		{"missing table", func(client *sentinelQualificationClient, _ *sentinelFixedClock) {
			client.metadata.Tables = client.metadata.Tables[:1]
			client.metadata.Digest = metadataDigest(client.metadata)
		}, queryconnector.Conflict, "sentinel_metadata_drift"},
		{"column type", func(client *sentinelQualificationClient, _ *sentinelFixedClock) {
			client.metadata.Tables[0].Columns[0].Type = "dynamic"
			client.metadata.Digest = metadataDigest(client.metadata)
		}, queryconnector.Conflict, "sentinel_metadata_drift"},
		{"invalid metadata digest", func(client *sentinelQualificationClient, _ *sentinelFixedClock) {
			client.metadata.Digest = sentinelTestDigest("9")
		}, queryconnector.Denied, "sentinel_metadata_invalid"},
		{"zero clock", func(_ *sentinelQualificationClient, clock *sentinelFixedClock) {
			clock.now = time.Time{}
		}, queryconnector.Denied, "sentinel_qualification_time_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			qualifier, client, config := sentinelTestQualifier(t)
			clock := qualifier.clock.(*sentinelFixedClock)
			test.mutate(client, clock)
			binding := sentinelTestBinding(config)
			_, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority)
			if queryconnector.Code(err) != test.code || queryconnector.Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", queryconnector.Code(err), queryconnector.Reason(err), err)
			}
		})
	}
}

func TestValidatedQualificationRejectsMutationCancellationAndPublishedFixture(t *testing.T) {
	if _, err := DecodeValidatedQualification(context.Background(), readFixture(t, "qualification.snapshot.json")); err != nil {
		t.Fatal(err)
	}
	qualifier, _, config := sentinelTestQualifier(t)
	binding := sentinelTestBinding(config)
	qualified, err := qualifier.Qualify(context.Background(), binding.Scope, binding.Authority)
	if err != nil {
		t.Fatal(err)
	}
	mutated := qualified.Value()
	mutated.Region = "eastus"
	encoded, _ := json.Marshal(mutated)
	if _, err := DecodeValidatedQualification(context.Background(), encoded); queryconnector.Reason(err) != "sentinel_qualification_document_invalid" {
		t.Fatalf("mutation err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeValidatedQualification(ctx, qualified.CanonicalBytes()); queryconnector.Code(err) != queryconnector.Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
}

func sentinelTestQualifier(t *testing.T) (*Qualifier, *sentinelQualificationClient, Config) {
	t.Helper()
	config, err := DecodeConfig(readFixture(t, "config.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := DecodeMetadata(readFixture(t, "metadata.snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	client := &sentinelQualificationClient{metadata: metadata, receipt: CallReceipt{RequestDigest: sentinelTestDigest("1"),
		ResponseDigest: sentinelTestDigest("2"), LeaseDecisionDigest: sentinelTestDigest("3"),
		TransportDigest: config.TransportIdentityDigest}}
	qualifier, err := NewQualifier(config, client, &sentinelFixedClock{now: sentinelTestNow})
	if err != nil {
		t.Fatal(err)
	}
	return qualifier, client, config
}
