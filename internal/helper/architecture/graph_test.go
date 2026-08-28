package architecture

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

type graphFixture struct {
	Packages []Package `json:"packages"`
}

func TestEvaluateAllowsDeclaredGraph(t *testing.T) {
	contract := loadContractFixture(t)
	graph := loadGraphFixture(t, "valid", "allowed-graph.json")
	report, err := Evaluate(context.Background(), contract, graph.Packages, testProvenance())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if report.Outcome != "allowed" || report.ViolationCount != 0 {
		t.Fatalf("report = %#v, want allowed with no violations", report)
	}
}

func TestEvaluateDeniesBrokerBypasses(t *testing.T) {
	contract := loadContractFixture(t)
	graph := loadGraphFixture(t, "invalid", "forbidden-graph.json")
	report, err := Evaluate(context.Background(), contract, graph.Packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.Outcome != "denied" || report.ViolationCount != 2 {
		t.Fatalf("report = %#v, want two denied imports", report)
	}
	if report.ContractDigest == "" || report.ContractVersion != "1.0.0" {
		t.Fatalf("denial report lost contract provenance: %#v", report)
	}
	wantSources := map[string]bool{"provider": false, "workflow": false}
	for _, violation := range report.Violations {
		if violation.Rule != "ARCH-002" {
			t.Fatalf("rule = %q, want ARCH-002", violation.Rule)
		}
		if violation.ImportBoundary != "connector" {
			t.Fatalf("import boundary = %q, want connector", violation.ImportBoundary)
		}
		wantSources[violation.Boundary] = true
	}
	for source, found := range wantSources {
		if !found {
			t.Fatalf("missing %s -> connector denial", source)
		}
	}
}

func TestEvaluateDeniesCommandAndRemoteConnectorBypasses(t *testing.T) {
	contract := loadContractFixture(t)
	tests := []struct {
		fixture   string
		wantCount int
	}{
		{fixture: "command-broker-bypass.json", wantCount: 2},
		{fixture: "remote-connector-bypass.json", wantCount: 1},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			graph := loadGraphFixture(t, "invalid", test.fixture)
			report, err := Evaluate(context.Background(), contract, graph.Packages, testProvenance())
			assertErrorCode(t, err, CodeDenied)
			if report.ViolationCount != test.wantCount {
				t.Fatalf("violation count = %d, want %d", report.ViolationCount, test.wantCount)
			}
		})
	}
}

func TestCapabilityCompositionImportsAreControlPlaneOnly(t *testing.T) {
	contract := loadContractFixture(t)
	target := ModulePath + "/internal/domain/capabilityseam"
	denied := loadGraphFixture(t, "invalid", "capability-composition-bypass.json")
	report, err := Evaluate(context.Background(), contract, denied.Packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 4 {
		t.Fatalf("composition bypass report = %#v", report)
	}
	for _, violation := range report.Violations {
		if violation.Rule != "ARCH-003" || violation.Import != target {
			t.Fatalf("composition violation = %#v", violation)
		}
	}
	for _, source := range []string{ModulePath + "/internal/command", ModulePath + "/internal/broker"} {
		report, err := Evaluate(context.Background(), contract,
			[]Package{{ImportPath: source, Imports: []string{target}}}, testProvenance())
		if err != nil || report.ViolationCount != 0 {
			t.Fatalf("%s control-plane import denied: report=%#v err=%v", source, report, err)
		}
	}
}

func TestProfileCompositionImportsAreCommandOnly(t *testing.T) {
	contract := loadContractFixture(t)
	target := ModulePath + "/internal/domain/profilecomposition"
	denied := loadGraphFixture(t, "invalid", "profile-composition-bypass.json")
	report, err := Evaluate(context.Background(), contract, denied.Packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 4 {
		t.Fatalf("profile composition bypass report = %#v", report)
	}
	for _, violation := range report.Violations {
		if violation.Rule != "ARCH-004" || violation.Import != target {
			t.Fatalf("profile composition violation = %#v", violation)
		}
	}
	report, err = Evaluate(context.Background(), contract,
		[]Package{{ImportPath: ModulePath + "/internal/command", Imports: []string{target}}}, testProvenance())
	if err != nil || report.ViolationCount != 0 {
		t.Fatalf("command profile import denied: report=%#v err=%v", report, err)
	}
}

func TestExtensionLifecycleImportsAreControlPlaneAndPersistenceOnly(t *testing.T) {
	contract := loadContractFixture(t)
	target := ModulePath + "/internal/domain/extensionlifecycle"
	denied := loadGraphFixture(t, "invalid", "extension-lifecycle-bypass.json")
	report, err := Evaluate(context.Background(), contract, denied.Packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 3 {
		t.Fatalf("extension lifecycle bypass report = %#v", report)
	}
	for _, violation := range report.Violations {
		if violation.Rule != "ARCH-005" || violation.Import != target {
			t.Fatalf("extension lifecycle violation = %#v", violation)
		}
	}
	for _, source := range []string{
		ModulePath + "/internal/command", ModulePath + "/internal/broker", ModulePath + "/internal/persistence/sqlite",
	} {
		report, err := Evaluate(context.Background(), contract,
			[]Package{{ImportPath: source, Imports: []string{target}}}, testProvenance())
		if err != nil || report.ViolationCount != 0 {
			t.Fatalf("%s extension lifecycle import denied: report=%#v err=%v", source, report, err)
		}
	}
}

func TestEvaluateCancellationAndRecovery(t *testing.T) {
	contract := loadContractFixture(t)
	graph := loadGraphFixture(t, "valid", "allowed-graph.json")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Evaluate(canceled, contract, graph.Packages, testProvenance())
	assertErrorCode(t, err, CodeCanceled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error does not preserve context cancellation: %v", err)
	}

	report, err := Evaluate(context.Background(), contract, graph.Packages, testProvenance())
	if err != nil {
		t.Fatalf("recovery Evaluate() error = %v", err)
	}
	if report.Outcome != "allowed" {
		t.Fatalf("recovery outcome = %q, want allowed", report.Outcome)
	}
}

func TestEvaluateRecoveryAfterDenial(t *testing.T) {
	contract := loadContractFixture(t)
	denied := loadGraphFixture(t, "invalid", "forbidden-graph.json")
	_, err := Evaluate(context.Background(), contract, denied.Packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)

	allowed := loadGraphFixture(t, "valid", "allowed-graph.json")
	report, err := Evaluate(context.Background(), contract, allowed.Packages, testProvenance())
	if err != nil {
		t.Fatalf("Evaluate() after denial error = %v", err)
	}
	if report.Outcome != "allowed" || report.ViolationCount != 0 {
		t.Fatalf("recovery report = %#v", report)
	}
}

func TestConnectorImportsAreBrokerOnly(t *testing.T) {
	for name, boundary := range requiredBoundaries {
		if name == "broker" || name == "connector" {
			continue
		}
		if slices.Contains(boundary.MayImport, "connector") {
			t.Fatalf("boundary %q can bypass broker and import connector", name)
		}
	}
}

func TestCommandAndWorkflowCannotReceiveSecurityImplementations(t *testing.T) {
	for _, name := range []string{"command", "workflow"} {
		boundary := requiredBoundaries[name]
		for _, forbidden := range []string{"connector", "policy"} {
			if slices.Contains(boundary.MayImport, forbidden) {
				t.Fatalf("boundary %q can import %q and bypass broker", name, forbidden)
			}
		}
	}
}

func TestEvaluateRejectsDuplicateAndUnclassifiedPackages(t *testing.T) {
	contract := loadContractFixture(t)
	unclassified := []Package{{ImportPath: ModulePath + "/internal/not-a-boundary"}}
	report, err := Evaluate(context.Background(), contract, unclassified, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 1 || report.Violations[0].Rule != "ARCH-001" {
		t.Fatalf("unclassified report = %#v", report)
	}

	duplicate := []Package{
		{ImportPath: ModulePath + "/internal/domain"},
		{ImportPath: ModulePath + "/internal/domain"},
	}
	_, err = Evaluate(context.Background(), contract, duplicate, testProvenance())
	assertErrorCode(t, err, CodeInvalidInput)
}

func TestListPackagesValidatesInputAndCancellation(t *testing.T) {
	_, err := ListPackages(context.Background(), "", ".", nil)
	assertErrorCode(t, err, CodeInvalidInput)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ListPackages(canceled, "go", ".", nil)
	assertErrorCode(t, err, CodeCanceled)

	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	_, err = ListPackages(expired, "go", ".", nil)
	assertErrorCode(t, err, CodeCanceled)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error does not preserve deadline: %v", err)
	}
}

func testProvenance() Provenance {
	return Provenance{
		SourceDigest: "fixture", VCSRevision: "fixture", CheckerVersion: CheckerVersion,
		GoVersion: "go1.26.7", GOOS: "test", GOARCH: "test", BuildTags: []string{},
	}
}

func loadGraphFixture(t *testing.T, class, name string) graphFixture {
	t.Helper()
	data := readFixture(t, class, name)
	var graph graphFixture
	if err := json.Unmarshal(data, &graph); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", name, err)
	}
	return graph
}
