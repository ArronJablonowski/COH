package runbudget

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestPublishedBudgetFixturesStrictlyDecodeAndAreCanonical(t *testing.T) {
	planBytes, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/run-budget-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := DecodePlan(planBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPlan, err := CanonicalPlan(plan)
	if err != nil || !bytes.Equal(bytes.TrimSpace(planBytes), canonicalPlan) {
		t.Fatalf("plan canonical=%s err=%v", canonicalPlan, err)
	}
	ledgerBytes, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/run-budget-ledger.json")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := DecodeLedger(ledgerBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalLedger, err := CanonicalLedger(ledger)
	if err != nil || !bytes.Equal(bytes.TrimSpace(ledgerBytes), canonicalLedger) {
		t.Fatalf("ledger canonical=%s err=%v", canonicalLedger, err)
	}
	if planDigestValue, digestErr := planDigest(plan); digestErr != nil || planDigestValue != ledger.PlanDigest {
		t.Fatalf("plan digest=%s ledger=%s err=%v", planDigestValue, ledger.PlanDigest, digestErr)
	}
}

func TestBudgetWireRejectsUnknownDuplicateMissingNestedTrailingAndOversized(t *testing.T) {
	valid, err := os.ReadFile("../../../contracts/workflow/v1/fixtures/run-budget-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string][]byte{
		"unknown":   append(append([]byte{}, valid[:len(valid)-2]...), []byte(`,"secret":"forbidden"}\n`)...),
		"duplicate": bytes.Replace(valid, []byte(`"run_id":"0199a213-1111-7111-8111-111111111111"`), []byte(`"run_id":"0199a213-1111-7111-8111-111111111111","run_id":"0199a213-1111-7111-8111-111111111111"`), 1),
		"missing":   bytes.Replace(valid, []byte(`"provider_route":"ollama.local",`), nil, 1),
		"nested":    bytes.Replace(valid, []byte(`"tokens":100,`), nil, 1),
		"trailing":  append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversized": bytes.Repeat([]byte{'x'}, maximumRecordBytes+1),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePlan(input); ErrorCode(err) != Denied {
				t.Fatalf("accepted malformed plan: %v", err)
			}
		})
	}
	unsupported := bytes.Replace(valid, []byte(`"contract_version":"1.0.0"`),
		[]byte(`"contract_version":"2.0.0"`), 1)
	if _, err := DecodePlan(unsupported); ErrorCode(err) != Denied && ErrorCode(err) != InvalidInput {
		t.Fatalf("accepted unsupported contract: %v", err)
	}
}

func TestBudgetWireRoundTripPreservesEveryLedgerField(t *testing.T) {
	store := &memoryLedgerStore{}
	controller := newTestController(t, store, &testClock{now: testNow})
	request := validReservation(testTask)
	reservation, err := controller.Reserve(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Settle(t.Context(), SettlementRequest{IdempotencyKey: "settle-wire",
		RunID: testRun, TaskID: testTask, Case: testScope(), ReservationDigest: reservation.ReservationDigest,
		Outcome: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalLedger(store.current)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLedger(encoded)
	if err != nil || !reflect.DeepEqual(decoded, store.current) {
		t.Fatalf("decoded=%+v current=%+v err=%v", decoded, store.current, err)
	}
}
