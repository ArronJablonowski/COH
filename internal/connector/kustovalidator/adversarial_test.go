package kustovalidator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestStaleRevokedAndReplayDenials(t *testing.T) {
	t.Run("stale schema", func(t *testing.T) {
		input, helper := serviceInput(t), &serviceHelper{}
		input.Schema.ValidUntil = serviceNow.Format(time.RFC3339Nano)
		service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, &serviceAudit{},
			NewMemoryReplayStore(), serviceClock{serviceNow})
		if _, err := service.Validate(context.Background(), input); err == nil || helper.calls != 0 {
			t.Fatalf("stale schema launched helper: %v", err)
		}
	})
	t.Run("signature drift", func(t *testing.T) {
		service, _ := NewService(&serviceHelper{}, &serviceAdmission{}, serviceTrust{err: errors.New("signature")},
			&serviceRevocation{}, &serviceAudit{}, NewMemoryReplayStore(), serviceClock{serviceNow})
		if _, err := service.Validate(context.Background(), serviceInput(t)); queryconnector.Code(err) != queryconnector.Denied {
			t.Fatalf("signature drift error = %v", err)
		}
	})
	t.Run("revoked helper", func(t *testing.T) {
		service, _ := NewService(&serviceHelper{}, &serviceAdmission{}, serviceTrust{},
			&serviceRevocation{denyPhase: "pre_helper"}, &serviceAudit{}, NewMemoryReplayStore(), serviceClock{serviceNow})
		if _, err := service.Validate(context.Background(), serviceInput(t)); queryconnector.Code(err) != queryconnector.Denied {
			t.Fatalf("revocation error = %v", err)
		}
	})
}

func TestConcurrentExactValidationCoalesces(t *testing.T) {
	input, helper := serviceInput(t), &serviceHelper{delay: 10 * time.Millisecond}
	service, _ := NewService(helper, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, &serviceAudit{},
		NewMemoryReplayStore(), serviceClock{serviceNow})
	results := make([]ValidationAdmission, 8)
	errorsFound := make([]error, len(results))
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errorsFound[index] = service.Validate(context.Background(), input)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsFound {
		if err != nil || results[index].CanonicalKQL == "" {
			t.Fatalf("result %d err=%v", index, err)
		}
	}
	if helper.calls != 1 {
		t.Fatalf("helper calls = %d, want 1", helper.calls)
	}
}

func TestAuditProofIsRedacted(t *testing.T) {
	service, _ := NewService(&serviceHelper{}, &serviceAdmission{}, serviceTrust{}, &serviceRevocation{}, &serviceAudit{},
		NewMemoryReplayStore(), serviceClock{serviceNow})
	admission, err := service.Validate(context.Background(), serviceInput(t))
	if err != nil {
		t.Fatal(err)
	}
	proof := admission.Audit
	if proof.QueryTextExposed || proof.LiteralExposed || proof.SchemaNameExposed || proof.WorkspaceExposed ||
		proof.CredentialExposed || proof.ExecutablePathExposed || proof.StderrExposed {
		t.Fatalf("audit leaked sensitive class: %+v", proof)
	}
}
