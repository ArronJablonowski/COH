package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
)

type custodyConcurrentResult struct {
	result custody.Result
	err    error
}

func TestCustodyConcurrentExactReplayHasOneAppend(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	driver, controller, ledger := concurrentCustodyFixture(t, now)
	defer driver.Close()
	command, _, _ := custodySQLiteFixture(now)
	const callers = 12
	start := make(chan struct{})
	results := make(chan custodyConcurrentResult, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := controller.Execute(context.Background(), command)
			results <- custodyConcurrentResult{result: result, err: err}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	created, receiptDigest := 0, ""
	for outcome := range results {
		if outcome.err != nil {
			t.Fatalf("concurrent exact replay: %v", outcome.err)
		}
		if !outcome.result.Replayed {
			created++
		}
		if receiptDigest == "" {
			receiptDigest = outcome.result.Receipt.ReceiptDigest
		} else if outcome.result.Receipt.ReceiptDigest != receiptDigest {
			t.Fatalf("callers recovered different receipts: %s != %s",
				outcome.result.Receipt.ReceiptDigest, receiptDigest)
		}
	}
	records, err := ledger.Read(context.Background(), command.Case, 0, 2)
	if err != nil || created != 1 || len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("created=%d records=%+v err=%v", created, records, err)
	}
}

func TestCustodyConcurrentChangedCommandsHaveOneHeadWinner(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	driver, controller, ledger := concurrentCustodyFixture(t, now)
	defer driver.Close()
	first, _, _ := custodySQLiteFixture(now)
	second := first
	second.RequestID = caseUUID("custody-concurrent-changed-request")
	second.IdempotencyKey = "sqlite-custody-concurrent-changed"
	commands := []custody.Command{first, second}
	start := make(chan struct{})
	results := make(chan custodyConcurrentResult, len(commands))
	var group sync.WaitGroup
	for _, command := range commands {
		group.Add(1)
		go func(value custody.Command) {
			defer group.Done()
			<-start
			result, err := controller.Execute(context.Background(), value)
			results <- custodyConcurrentResult{result: result, err: err}
		}(command)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for outcome := range results {
		if outcome.err == nil {
			succeeded++
		} else if custody.CodeOf(outcome.err) == custody.Conflict {
			conflicted++
		} else {
			t.Fatalf("unexpected competing result: %v", outcome.err)
		}
	}
	records, err := ledger.Read(context.Background(), first.Case, 0, 2)
	if err != nil || succeeded != 1 || conflicted != 1 || len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("success=%d conflict=%d records=%+v err=%v", succeeded, conflicted, records, err)
	}
}

func concurrentCustodyFixture(t *testing.T, now time.Time) (*sqlite.Store, *custody.Controller,
	*custody.RepositoryStore) {
	t.Helper()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	_, current, verified := custodySQLiteFixture(now)
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		driver.Close()
		t.Fatal(err)
	}
	ledger, err := custody.NewRepositoryStore(guarded)
	if err != nil {
		driver.Close()
		t.Fatal(err)
	}
	auditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof)}
	controller, err := custody.New(custodySQLiteAuthority{now: now}, custodySQLiteCases{current: current},
		custodySQLiteEvidence{verified: verified}, ledger, auditor, custodySQLiteClock{now: now})
	if err != nil {
		driver.Close()
		t.Fatal(err)
	}
	return driver, controller, ledger
}
