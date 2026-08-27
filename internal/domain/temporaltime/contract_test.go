package temporaltime

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEVAL017ExecutableFixtureMatrix(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "time", "v1", "fixtures", "eval-017.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion   string   `json:"schema_version"`
		ContractVersion string   `json:"contract_version"`
		Requirements    []string `json:"requirements"`
		Cases           []struct {
			Name            string `json:"name"`
			ExpectedOutcome string `json:"expected_outcome"`
			ExpectedReason  string `json:"expected_reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(input, &fixture); err != nil || fixture.SchemaVersion != "coh.eval-017-time-fixtures/v1" ||
		fixture.ContractVersion != ContractVersion || !reflect.DeepEqual(fixture.Requirements, []string{"FR-024", "EVAL-017"}) || len(fixture.Cases) != 15 {
		t.Fatalf("fixture=%+v err=%v", fixture, err)
	}
	seen := make(map[string]struct{}, len(fixture.Cases))
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			outcome, reason := executeEVAL017(t, test.Name)
			if outcome != test.ExpectedOutcome || reason != test.ExpectedReason {
				t.Fatalf("outcome=%s reason=%s want=%s/%s", outcome, reason, test.ExpectedOutcome, test.ExpectedReason)
			}
		})
		if _, exists := seen[test.Name]; exists {
			t.Fatalf("duplicate fixture %s", test.Name)
		}
		seen[test.Name] = struct{}{}
	}
}

func TestCanonicalCommandRetainsExactBindingsAndSourceText(t *testing.T) {
	command := testCommand()
	canonical, digest, err := CanonicalCommand(context.Background(), command)
	if err != nil || !digestPattern.MatchString(digest) || !bytes.Contains(canonical, []byte(`"text":" 2026-11-01 01:30:00 "`)) {
		t.Fatalf("canonical=%s digest=%s err=%v", canonical, digest, err)
	}
	decoded, recovered, recoveredDigest, err := DecodeCommand(context.Background(), append([]byte(" \n"), canonical...))
	if err != nil || !reflect.DeepEqual(decoded, command) || !bytes.Equal(recovered, canonical) || recoveredDigest != digest {
		t.Fatalf("decoded=%+v digest=%s err=%v", decoded, recoveredDigest, err)
	}

	var object map[string]any
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	changed, _ := json.Marshal(object)
	if _, _, _, err := DecodeCommand(context.Background(), changed); Code(err) != InvalidInput {
		t.Fatalf("unknown field err=%v", err)
	}
	duplicate := bytes.Replace(canonical, []byte(`"contract_version":"1.0.0"`), []byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1)
	if _, _, _, err := DecodeCommand(context.Background(), duplicate); Code(err) != InvalidInput {
		t.Fatalf("duplicate key err=%v", err)
	}
}

func TestBuildRecordAppliesPrecisionSkewAndRadius(t *testing.T) {
	command := testCommand()
	command.Timezone = offsetAssertion(-420)
	command.OriginalTime.Precision = Second
	command.OriginalTime.Text = "2026-08-27T12:00:00-07:00"
	civil := CivilTime{Year: 2026, Month: time.August, Day: 27, Hour: 12, Precision: Second}
	resolution := TimezoneResolution{DSTState: DSTNotApplicable, Intervals: []ResolvedInterval{{
		EarliestUTC: mustTime("2026-08-27T19:00:00.000000000Z"), LatestUTC: mustTime("2026-08-27T19:00:00.999999999Z"), OffsetMinutes: -420,
	}}}
	record, err := BuildRecord(context.Background(), command, civil, resolution, command.Calibration, mustTime("2026-08-27T20:00:00.000000000Z"))
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != Normalized || record.ReasonCode != ReasonNormalized || record.NormalizedUTC == nil ||
		*record.NormalizedUTC != "2026-08-27T18:59:58.000000000Z" || *record.Interval.EarliestUTC != "2026-08-27T18:59:57.000000000Z" ||
		*record.Interval.LatestUTC != "2026-08-27T18:59:59.999999999Z" || record.OriginalTime.Text != command.OriginalTime.Text {
		t.Fatalf("record=%+v", record)
	}
	if _, _, err := CanonicalRecord(context.Background(), record); err != nil {
		t.Fatalf("canonical record: %v", err)
	}
}

func TestMissingTimezoneAndDSTGapNeverInventUTC(t *testing.T) {
	command := testCommand()
	command.Timezone = TimezoneAssertion{Kind: MissingTimezone}
	record, err := BuildRecord(context.Background(), command, testCivil(), TimezoneResolution{DSTState: DSTUnresolved}, command.Calibration, testNow())
	if err != nil || record.Outcome != Unresolved || record.ReasonCode != TimezoneUnresolved || record.NormalizedUTC != nil || record.Interval.Kind != Unbounded {
		t.Fatalf("missing record=%+v err=%v", record, err)
	}

	command.Timezone = ianaAssertion()
	record, err = BuildRecord(context.Background(), command, testCivil(), TimezoneResolution{DSTState: DSTGapState}, command.Calibration, testNow())
	if err != nil || record.Outcome != Unresolved || record.ReasonCode != DSTGap || record.NormalizedUTC != nil || record.Interval.Kind != Unbounded {
		t.Fatalf("gap record=%+v err=%v", record, err)
	}
}

func TestDSTFoldRetainsBothCandidatesWithoutSelectingOne(t *testing.T) {
	command := testCommand()
	command.Timezone = ianaAssertion()
	resolution := TimezoneResolution{DSTState: DSTFold, Intervals: []ResolvedInterval{
		{EarliestUTC: mustTime("2026-11-01T07:30:00.000000000Z"), LatestUTC: mustTime("2026-11-01T07:30:00.999999999Z"), OffsetMinutes: -360},
		{EarliestUTC: mustTime("2026-11-01T08:30:00.000000000Z"), LatestUTC: mustTime("2026-11-01T08:30:00.999999999Z"), OffsetMinutes: -420},
	}}
	record, err := BuildRecord(context.Background(), command, testCivil(), resolution, command.Calibration, testNow())
	if err != nil || record.Outcome != Unresolved || record.NormalizedUTC != nil || record.Interval.Kind != Bounded || len(record.CandidateUTC) != 2 ||
		*record.Interval.EarliestUTC != "2026-11-01T07:29:57.000000000Z" || *record.Interval.LatestUTC != "2026-11-01T08:29:59.999999999Z" {
		t.Fatalf("fold record=%+v err=%v", record, err)
	}
	if _, _, err := CanonicalRecord(context.Background(), record); err != nil {
		t.Fatalf("canonical fold record: %v", err)
	}
}

func TestSkewArithmeticOverflowIsDenied(t *testing.T) {
	command := testCommand()
	maximum, one := int64(math.MaxInt64), int64(1)
	command.Calibration.EstimateNanoseconds = &maximum
	command.Calibration.RadiusNanoseconds = &one
	command.Timezone = offsetAssertion(0)
	resolution := TimezoneResolution{DSTState: DSTNotApplicable, Intervals: []ResolvedInterval{{EarliestUTC: testNow(), LatestUTC: testNow(), OffsetMinutes: 0}}}
	if _, err := BuildRecord(context.Background(), command, testCivil(), resolution, command.Calibration, testNow()); Code(err) != DeniedError || ErrorReason(err) != ArithmeticOverflow {
		t.Fatalf("overflow err=%v", err)
	}
}

func TestStrictParserRegistryAcceptsOnlyPinnedExplicitFormats(t *testing.T) {
	identity := testCommand().Parser
	registry, err := NewStrictParserRegistry([]ParserSpec{{Identity: identity, Kind: BuiltinStrictParser}})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := registry.ResolveParser(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse(context.Background(), "2026-11-01T01:30:00-06:00", "rfc3339", Second)
	if err != nil || parsed.SourceOffsetMinutes == nil || *parsed.SourceOffsetMinutes != -360 || parsed.Hour != 1 || parsed.Precision != Second {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	if _, err := parser.Parse(context.Background(), "2026/11/01 01:30", "dynamic_layout", Minute); Code(err) != DeniedError || ErrorReason(err) != FormatNotSupported {
		t.Fatalf("dynamic format err=%v", err)
	}
	changed := identity
	changed.Version = "1.0.1"
	if _, err := registry.ResolveParser(context.Background(), changed); Code(err) != DeniedError || ErrorReason(err) != ParserNotRegistered {
		t.Fatalf("unpinned parser err=%v", err)
	}
}

func TestPinnedTimezoneResolverPreservesDSTGapFoldAndDayWidth(t *testing.T) {
	location, err := time.LoadLocation("America/Denver")
	if err != nil {
		t.Fatal(err)
	}
	assertion := ianaAssertion()
	resolver, err := NewPinnedTimezoneResolver(assertion.TZDataVersion, assertion.TZDataDigest, map[string]*time.Location{assertion.Name: location})
	if err != nil {
		t.Fatal(err)
	}
	gap, err := resolver.ResolveCivil(context.Background(), CivilTime{Year: 2026, Month: time.March, Day: 8, Hour: 2, Minute: 30, Precision: Minute}, assertion)
	if err != nil || gap.DSTState != DSTGapState || len(gap.Intervals) != 0 {
		t.Fatalf("gap=%+v err=%v", gap, err)
	}
	foldCivil := CivilTime{Year: 2026, Month: time.November, Day: 1, Hour: 1, Minute: 30, Precision: Minute}
	fold, err := resolver.ResolveCivil(context.Background(), foldCivil, assertion)
	if err != nil || fold.DSTState != DSTFold || len(fold.Intervals) != 2 || fold.Intervals[0].OffsetMinutes != -360 || fold.Intervals[1].OffsetMinutes != -420 {
		t.Fatalf("fold=%+v err=%v", fold, err)
	}
	selectedOffset := int16(-360)
	assertion.OffsetMinutes = &selectedOffset
	selected, err := resolver.ResolveCivil(context.Background(), foldCivil, assertion)
	if err != nil || selected.DSTState != DSTFold || len(selected.Intervals) != 1 || selected.Intervals[0].OffsetMinutes != -360 {
		t.Fatalf("selected fold=%+v err=%v", selected, err)
	}
	assertion.OffsetMinutes = nil
	day, err := resolver.ResolveCivil(context.Background(), CivilTime{Year: 2026, Month: time.March, Day: 8, Precision: Day}, assertion)
	if err != nil || day.DSTState != DSTExact || len(day.Intervals) != 1 || day.Intervals[0].LatestUTC.Sub(day.Intervals[0].EarliestUTC) != 23*time.Hour-time.Nanosecond {
		t.Fatalf("day=%+v width=%v err=%v", day, day.Intervals[0].LatestUTC.Sub(day.Intervals[0].EarliestUTC), err)
	}
	changed := assertion
	changed.TZDataVersion = "unverified"
	if _, err := resolver.ResolveCivil(context.Background(), foldCivil, changed); Code(err) != DeniedError || ErrorReason(err) != TimezoneMismatch {
		t.Fatalf("tzdata mismatch err=%v", err)
	}
}

func TestSourceOffsetMustBindTimezoneAssertion(t *testing.T) {
	command := testCommand()
	command.Timezone = ianaAssertion()
	sourceOffset := int16(-360)
	civil := testCivil()
	civil.SourceOffsetMinutes = &sourceOffset
	resolution := TimezoneResolution{DSTState: DSTFold, Intervals: []ResolvedInterval{{
		EarliestUTC: mustTime("2026-11-01T07:30:00.000000000Z"), LatestUTC: mustTime("2026-11-01T07:30:00.999999999Z"), OffsetMinutes: -360,
	}}}
	if _, err := BuildRecord(context.Background(), command, civil, resolution, command.Calibration, testNow()); Code(err) != ConflictError || ErrorReason(err) != TimezoneMismatch {
		t.Fatalf("unbound source offset err=%v", err)
	}
	command.Timezone.OffsetMinutes = &sourceOffset
	record, err := BuildRecord(context.Background(), command, civil, resolution, command.Calibration, testNow())
	if err != nil || record.Outcome != Normalized || record.TimezoneResult.DSTState != DSTFold || record.NormalizedUTC == nil {
		t.Fatalf("bound fold record=%+v err=%v", record, err)
	}
}

func TestComparisonNeverOrdersOverlappingOrUnresolvedIntervals(t *testing.T) {
	left := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000021", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "2026-08-27T19:00:00.000000000Z")
	right := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000022", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "2026-08-27T19:00:01.000000000Z")
	comparison, err := CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000031", left, right, testNow())
	if err != nil || comparison.Outcome != Before || comparison.Confidence != Exact || comparison.GapNanoseconds == nil || *comparison.GapNanoseconds != 999999999 {
		t.Fatalf("before=%+v err=%v", comparison, err)
	}

	right.Interval.EarliestUTC = left.Interval.EarliestUTC
	right.Interval.LatestUTC = left.Interval.LatestUTC
	right.NormalizedUTC = left.NormalizedUTC
	comparison, err = CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000032", left, right, testNow())
	if err != nil || comparison.Outcome != Equal {
		t.Fatalf("equal=%+v err=%v", comparison, err)
	}

	right.Interval.LatestUTC = stringPointer("2026-08-27T19:00:02.000000000Z")
	comparison, err = CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000033", left, right, testNow())
	if err != nil || comparison.Outcome != Overlap {
		t.Fatalf("overlap=%+v err=%v", comparison, err)
	}

	unresolved := left
	unresolved.Outcome, unresolved.ReasonCode, unresolved.NormalizedUTC, unresolved.Interval = Unresolved, TimezoneUnresolved, nil, Interval{Kind: Unbounded}
	comparison, err = CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000034", unresolved, right, testNow())
	if err != nil || comparison.Outcome != UnknownComparison || comparison.Rationale != UnboundedInterval {
		t.Fatalf("unknown=%+v err=%v", comparison, err)
	}
}

func TestComparisonDuplicateAndConflictPrecedeOrdering(t *testing.T) {
	left := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000041", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "2026-08-27T19:00:00.000000000Z")
	comparison, err := CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000042", left, left, testNow())
	if err != nil || comparison.Outcome != Duplicate || comparison.Rationale != SameBindingSameRecord {
		t.Fatalf("duplicate=%+v err=%v", comparison, err)
	}
	right := left
	right.CreatedAt = "2026-08-27T20:00:00.000000001Z"
	comparison, err = CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000043", left, right, testNow())
	if err != nil || comparison.Outcome != Conflict || comparison.Rationale != SameBindingIncompatibleFacts {
		t.Fatalf("conflict=%+v err=%v", comparison, err)
	}
}

func TestContextCancellationAndBoundarySurface(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := CanonicalCommand(canceled, testCommand()); Code(err) != Canceled {
		t.Fatalf("canceled err=%v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	if _, _, err := CanonicalCommand(deadline, testCommand()); Code(err) != Timeout {
		t.Fatalf("timeout err=%v", err)
	}

	for _, value := range []any{Dependencies{}, SourceBinding{}, Command{}, Record{}, Commit{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if hasForbiddenName(typeOf.Field(index).Name) {
				t.Fatalf("%s exposes forbidden field %s", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
	for _, port := range []any{
		(*EvidenceVerifier)(nil), (*ParserRegistry)(nil), (*TimezoneResolver)(nil), (*CalibrationResolver)(nil),
		(*RecordStore)(nil), (*AuditBuilder)(nil), (*ProvenanceBuilder)(nil), (*Clock)(nil),
	} {
		typeOf := reflect.TypeOf(port).Elem()
		for index := 0; index < typeOf.NumMethod(); index++ {
			method := strings.ToLower(typeOf.Method(index).Name)
			for _, forbidden := range []string{"shell", "http", "sql", "credential", "secret", "executor", "connector"} {
				if strings.Contains(method, forbidden) {
					t.Fatalf("%s exposes %s", typeOf.Name(), method)
				}
			}
		}
	}
}

func FuzzDecodeCommandRoundTrip(f *testing.F) {
	canonical, _, err := CanonicalCommand(context.Background(), testCommand())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canonical)
	f.Fuzz(func(t *testing.T, input []byte) {
		command, recovered, digest, err := DecodeCommand(context.Background(), input)
		if err != nil {
			return
		}
		again, againDigest, err := CanonicalCommand(context.Background(), command)
		if err != nil || !bytes.Equal(again, recovered) || againDigest != digest {
			t.Fatalf("accepted command did not recover: %v", err)
		}
	})
}

func executeEVAL017(t *testing.T, name string) (string, string) {
	t.Helper()
	switch name {
	case "explicit-utc-nanoseconds":
		record := evalOffsetRecord(t, Nanosecond, 0, 0, 0, Observed, Complete)
		return string(record.Outcome), string(record.ReasonCode)
	case "numeric-offset":
		record := evalOffsetRecord(t, Second, -420, 0, 0, Observed, Complete)
		return string(record.Outcome), string(record.ReasonCode)
	case "dst-spring-gap", "dst-fall-fold", "low-precision-day":
		return executeDSTFixture(t, name)
	case "missing-timezone":
		command := testCommand()
		command.Timezone = TimezoneAssertion{Kind: MissingTimezone}
		record, err := BuildRecord(context.Background(), command, testCivil(), TimezoneResolution{DSTState: DSTUnresolved}, command.Calibration, testNow())
		if err != nil {
			t.Fatal(err)
		}
		return string(record.Outcome), string(record.ReasonCode)
	case "positive-clock-skew":
		record := evalOffsetRecord(t, Second, 0, int64(5*time.Second), int64(time.Second), Observed, Complete)
		return string(record.Outcome), string(record.ReasonCode)
	case "negative-clock-skew":
		record := evalOffsetRecord(t, Second, 0, -int64(5*time.Second), int64(time.Second), Observed, Complete)
		return string(record.Outcome), string(record.ReasonCode)
	case "arithmetic-overflow":
		command := testCommand()
		command.Timezone = offsetAssertion(0)
		maximum, one := int64(math.MaxInt64), int64(1)
		command.Calibration.EstimateNanoseconds, command.Calibration.RadiusNanoseconds = &maximum, &one
		instant := mustTime("2026-08-27T19:00:00.000000000Z")
		_, err := BuildRecord(context.Background(), command, testCivil(), TimezoneResolution{DSTState: DSTNotApplicable, Intervals: []ResolvedInterval{{EarliestUTC: instant, LatestUTC: instant, OffsetMinutes: 0}}}, command.Calibration, testNow())
		return string(Denied), string(ErrorReason(err))
	case "duplicate-record":
		left := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000091", digestOf('c'), "2026-08-27T19:00:00.000000000Z")
		comparison, err := CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000092", left, left, testNow())
		if err != nil {
			t.Fatal(err)
		}
		return string(comparison.Outcome), string(comparison.Rationale)
	case "uncertain-order":
		left := evalOffsetRecord(t, Second, 0, 0, int64(time.Second), Observed, Complete)
		right := left
		right.RecordID, right.OperationID = "0199a401-1000-7000-8000-000000000093", "0199a401-1000-7000-8000-000000000093"
		right.SourceBinding.DeduplicationDigest = digestOf('d')
		comparison, err := CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000094", left, right, testNow())
		if err != nil {
			t.Fatal(err)
		}
		return string(comparison.Outcome), string(comparison.Rationale)
	case "source-conflict":
		left := exactRecordFixture(t, "0199a401-1000-7000-8000-000000000095", digestOf('e'), "2026-08-27T19:00:00.000000000Z")
		right := left
		right.RecordID, right.OperationID, right.CreatedAt = "0199a401-1000-7000-8000-000000000096", "0199a401-1000-7000-8000-000000000096", "2026-08-27T20:00:00.000000001Z"
		comparison, err := CompareRecords(context.Background(), "0199a401-1000-7000-8000-000000000097", left, right, testNow())
		if err != nil {
			t.Fatal(err)
		}
		return string(comparison.Outcome), string(comparison.Rationale)
	case "partial-data":
		record := evalOffsetRecord(t, Second, 0, 0, 0, Partial, PartialCompleteness)
		if record.EvidenceState != Partial || record.Completeness != PartialCompleteness {
			t.Fatal("partial state lost")
		}
		return string(record.Outcome), string(record.ReasonCode)
	case "negative-evidence":
		record := evalOffsetRecord(t, Second, 0, 0, 0, Negative, Complete)
		if record.EvidenceState != Negative {
			t.Fatal("negative evidence lost")
		}
		return string(record.Outcome), string(record.ReasonCode)
	case "explicit-gap-evidence":
		record := evalOffsetRecord(t, Second, 0, 0, 0, Gap, Complete)
		if record.EvidenceState != Gap {
			t.Fatal("gap evidence lost")
		}
		return string(record.Outcome), string(record.ReasonCode)
	default:
		t.Fatalf("unimplemented EVAL-017 fixture %s", name)
		return "", ""
	}
}

func evalOffsetRecord(t *testing.T, precision Precision, offset int16, estimate, radius int64, evidence EvidenceState, completeness Completeness) Record {
	t.Helper()
	command := testCommand()
	command.Timezone = offsetAssertion(offset)
	command.OriginalTime.Precision = precision
	command.EvidenceState, command.Completeness = evidence, completeness
	command.Calibration.EstimateNanoseconds, command.Calibration.RadiusNanoseconds = &estimate, &radius
	start := mustTime("2026-08-27T19:00:00.000000000Z")
	end := start
	if precision == Second {
		end = start.Add(time.Second - time.Nanosecond)
	}
	civil := CivilTime{Year: 2026, Month: time.August, Day: 27, Hour: 12, Precision: precision}
	record, err := BuildRecord(context.Background(), command, civil, TimezoneResolution{DSTState: DSTNotApplicable, Intervals: []ResolvedInterval{{EarliestUTC: start, LatestUTC: end, OffsetMinutes: offset}}}, command.Calibration, testNow())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func executeDSTFixture(t *testing.T, name string) (string, string) {
	t.Helper()
	location, err := time.LoadLocation("America/Denver")
	if err != nil {
		t.Fatal(err)
	}
	assertion := ianaAssertion()
	resolver, err := NewPinnedTimezoneResolver(assertion.TZDataVersion, assertion.TZDataDigest, map[string]*time.Location{assertion.Name: location})
	if err != nil {
		t.Fatal(err)
	}
	command := testCommand()
	command.Timezone = assertion
	civil := testCivil()
	if name == "dst-spring-gap" {
		civil = CivilTime{Year: 2026, Month: time.March, Day: 8, Hour: 2, Minute: 30, Precision: Minute}
		command.OriginalTime.Precision = Minute
	} else if name == "low-precision-day" {
		civil = CivilTime{Year: 2026, Month: time.March, Day: 8, Precision: Day}
		command.OriginalTime.Precision = Day
	}
	resolution, err := resolver.ResolveCivil(context.Background(), civil, assertion)
	if err != nil {
		t.Fatal(err)
	}
	record, err := BuildRecord(context.Background(), command, civil, resolution, command.Calibration, testNow())
	if err != nil {
		t.Fatal(err)
	}
	return string(record.Outcome), string(record.ReasonCode)
}

func testCommand() Command {
	estimate, radius := int64(2*time.Second), int64(time.Second)
	return Command{
		SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		OperationID: "0199a401-1000-7000-8000-000000000001", IdempotencyKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Case: Case{OrganizationID: "0199a401-1000-7000-8000-000000000002", TenantID: "0199a401-1000-7000-8000-000000000003", CaseID: "0199a401-1000-7000-8000-000000000004"},
		SourceBinding: SourceBinding{
			EnvelopeID: "0199a401-1000-7000-8000-000000000005", EnvelopeDigest: digestOf('2'), ArtifactDigest: digestOf('3'), ManifestDigest: digestOf('4'),
			IngestReceiptDigest: digestOf('5'), SourceProvenanceDigest: digestOf('6'), SourceIdentityDigest: digestOf('7'), FieldSelector: "original.event.created", DeduplicationDigest: digestOf('8'),
		},
		OriginalTime: OriginalTime{Text: " 2026-11-01 01:30:00 ", Format: "vendor_local", Precision: Second},
		Parser:       ParserIdentity{Name: "vendor_time", Version: "1.0.0", Digest: digestOf('9')}, Timezone: ianaAssertion(),
		Calibration:   Calibration{State: KnownCalibration, ClockKind: DeviceClock, Identity: "sensor-17/ntp-4", IdentityDigest: digestOf('a'), EstimateNanoseconds: &estimate, RadiusNanoseconds: &radius},
		EvidenceState: Observed, Completeness: Complete, RequestedAt: "2026-08-27T19:00:00.000000000Z", Deadline: "2026-08-27T19:00:05.000000000Z",
	}
}

func exactRecordFixture(t *testing.T, operationID, deduplicationDigest, instant string) Record {
	t.Helper()
	command := testCommand()
	command.OperationID = operationID
	command.IdempotencyKey = digestBytes([]byte(operationID))
	command.SourceBinding.DeduplicationDigest = deduplicationDigest
	command.Timezone = offsetAssertion(0)
	zero := int64(0)
	command.Calibration.EstimateNanoseconds, command.Calibration.RadiusNanoseconds = &zero, &zero
	parsed := mustTime(instant)
	civil := CivilTime{Year: parsed.Year(), Month: parsed.Month(), Day: parsed.Day(), Hour: parsed.Hour(), Minute: parsed.Minute(), Second: parsed.Second(), Nanosecond: parsed.Nanosecond(), Precision: Nanosecond}
	command.OriginalTime.Precision = Nanosecond
	resolution := TimezoneResolution{DSTState: DSTNotApplicable, Intervals: []ResolvedInterval{{EarliestUTC: parsed, LatestUTC: parsed, OffsetMinutes: 0}}}
	record, err := BuildRecord(context.Background(), command, civil, resolution, command.Calibration, testNow())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testCivil() CivilTime {
	return CivilTime{Year: 2026, Month: time.November, Day: 1, Hour: 1, Minute: 30, Precision: Second}
}
func testNow() time.Time { return mustTime("2026-08-27T20:00:00.000000000Z") }

func ianaAssertion() TimezoneAssertion {
	return TimezoneAssertion{Kind: IANA, Name: "America/Denver", TZDataVersion: "2026b", TZDataDigest: digestOf('b')}
}

func offsetAssertion(value int16) TimezoneAssertion {
	return TimezoneAssertion{Kind: ExplicitOffset, OffsetMinutes: &value}
}

func digestOf(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }

func mustTime(value string) time.Time {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func stringPointer(value string) *string { return &value }
