package lifecyclecase

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestCommandForMapsSupportedEvidenceLifecycleOperationsDeterministically(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	reason, manifest := lifecycleCaseDigest("reason"), lifecycleCaseDigest("manifest")
	tests := []struct {
		name      string
		operation evidencelifecycle.Operation
		reason    *string
		manifest  *string
		want      caselifecycle.Operation
	}{
		{name: "export", operation: evidencelifecycle.Export, manifest: &manifest, want: caselifecycle.Export},
		{name: "place hold", operation: evidencelifecycle.PlaceHold, reason: &reason, want: caselifecycle.PlaceHold},
		{name: "release hold", operation: evidencelifecycle.ReleaseHold, reason: &reason, want: caselifecycle.ReleaseHold},
		{name: "delete", operation: evidencelifecycle.Delete, reason: &reason, want: caselifecycle.Delete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := lifecycleCaseRequest(now)
			request.Operation, request.ReasonDigest, request.ManifestDigest = test.operation, test.reason, test.manifest
			first, err := commandFor(request)
			if err != nil {
				t.Fatal(err)
			}
			second, err := commandFor(request)
			if err != nil {
				t.Fatal(err)
			}
			firstCanonical, err := caselifecycle.CanonicalCommand(first)
			if err != nil {
				t.Fatal(err)
			}
			secondCanonical, err := caselifecycle.CanonicalCommand(second)
			if err != nil {
				t.Fatal(err)
			}
			if first.Operation != test.want || !bytes.Equal(firstCanonical, secondCanonical) ||
				first.ExpectedRevision != request.ExpectedCaseRevision {
				t.Fatalf("first=%+v second=%+v", first, second)
			}
		})
	}
}

func TestCommandForRejectsUnsupportedOrAmbiguousRequests(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	reason, manifest := lifecycleCaseDigest("reason"), lifecycleCaseDigest("manifest")
	tests := []evidencelifecycle.LifecycleRequest{
		lifecycleCaseRequest(now),
		func() evidencelifecycle.LifecycleRequest {
			value := lifecycleCaseRequest(now)
			value.Operation, value.ReasonDigest, value.ManifestDigest = evidencelifecycle.Export, &reason, &manifest
			return value
		}(),
		func() evidencelifecycle.LifecycleRequest {
			value := lifecycleCaseRequest(now)
			value.Operation, value.ManifestDigest, value.IdempotencyDigest = evidencelifecycle.Export, &manifest, "invalid"
			return value
		}(),
	}
	for index, request := range tests {
		if _, err := commandFor(request); evidencelifecycle.CodeOf(err) != evidencelifecycle.InvalidInput {
			t.Fatalf("request %d err=%v", index, err)
		}
	}
}

func lifecycleCaseRequest(now time.Time) evidencelifecycle.LifecycleRequest {
	return evidencelifecycle.LifecycleRequest{Case: domain.CaseRef{
		OrganizationID: deterministicUUID("test\x00", "org"),
		TenantID:       deterministicUUID("test\x00", "tenant"),
		CaseID:         deterministicUUID("test\x00", "case"),
	}, ActorID: deterministicUUID("test\x00", "actor"), ActorRevision: 3,
		ExpectedCaseRevision: 2, PolicyDigest: lifecycleCaseDigest("policy"),
		IdempotencyDigest: lifecycleCaseDigest("idempotency"), Deadline: now}
}

func lifecycleCaseDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
