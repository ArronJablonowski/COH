package normalizedevent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const expectedEventDigest = "sha256:c42828417bbccb979c063efb1bf0da359b96baf94fc145d9576c005cfbba9d00"

func TestCanonicalFixturesPreserveSourceOCSFAndECS(t *testing.T) {
	for _, name := range []string{"event.canonical.json", "dataset-event.canonical.json"} {
		input := readFixture(t, "valid", name)
		validated, err := Decode(context.Background(), input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(validated.CanonicalBytes(), bytes.TrimSpace(input)) {
			t.Fatalf("%s is not canonical", name)
		}
		value := validated.Value()
		if !bytes.Contains(value.Original.Fields, []byte(`"winlog":{"event_id":4624}`)) || value.ECS == nil ||
			!bytes.Contains(value.ECS.Fields, []byte(`"ecs":{"version":"9.5.0"}`)) ||
			!bytes.Contains(value.OCSF.Event, []byte(`"class_uid":3002`)) {
			t.Fatalf("%s did not preserve representations", name)
		}
		if name == "event.canonical.json" && validated.Digest() != expectedEventDigest {
			t.Fatalf("event digest=%s", validated.Digest())
		}
		copyBytes := validated.CanonicalBytes()
		copyBytes[0] = '['
		copyValue := validated.Value()
		copyValue.Original.Fields[0] = '['
		if validated.CanonicalBytes()[0] != '{' || validated.Value().Original.Fields[0] != '{' {
			t.Fatal("validated envelope exposed mutable state")
		}
		again, err := Decode(context.Background(), validated.CanonicalBytes())
		if err != nil || again.Digest() != validated.Digest() {
			t.Fatalf("round trip digest=%s err=%v", again.Digest(), err)
		}
	}
}

func TestStrictDenialCorpus(t *testing.T) {
	base := bytes.TrimSpace(readFixture(t, "valid", "event.canonical.json"))
	mutations := map[string]func([]byte) []byte{
		"duplicate-key": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"contract_version":"1.0.0"`), []byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1)
		},
		"unknown-envelope-field": func(input []byte) []byte {
			return append([]byte(`{"unexpected":true,`), input[1:]...)
		},
		"unsupported-ocsf-target": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"ocsf_version":"1.9.0"`), []byte(`"ocsf_version":"1.8.0"`), 1)
		},
		"missing-raw-manifest": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"raw_manifest_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",`), nil, 1)
		},
		"original-field-mutation": func(input []byte) []byte {
			return mutateAfter(input, `"original":`, `"event_id":4624`, `"event_id":4625`)
		},
		"ocsf-type-mismatch": func(input []byte) []byte {
			changed := bytes.Replace(input, []byte(`"type_uid":300201`), []byte(`"type_uid":300202`), 1)
			return bytes.Replace(changed, []byte(`03ea1fdcb73ae1e67a14e0fe2ca8e5042c44c6741b57426691a792b1e11219bc`), []byte(`05618402a8893c4be33d160c769c97241ccda0da483cdb12c13352ec23040595`), 1)
		},
		"classification-downgrade": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"classification":"confidential"`), []byte(`"classification":"public"`), 1)
		},
		"changed-transformation": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`47548d56e28f4a3f2be2147236ec8c3c192e0a7758c1d9d1e7677f0088722ef8`), []byte(`07548d56e28f4a3f2be2147236ec8c3c192e0a7758c1d9d1e7677f0088722ef8`), 1)
		},
		"unsorted-lineage": func(input []byte) []byte {
			parents := `"parent_envelope_digests":["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]`
			return bytes.Replace(input, []byte(`"parent_envelope_digests":[]`), []byte(parents), 1)
		},
		"direct-dataset-path": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"dataset":null`), []byte(`"dataset":{"path":"/tmp/events.parquet"}`), 1)
		},
		"noncanonical-decimal": func(input []byte) []byte {
			return mutateAfter(input, `"original":`, `"event_id":4624`, `"event_id":4624,"score":0.120`)
		},
	}

	var corpus struct {
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		Cases           []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil ||
		corpus.SchemaVersion != "coh.normalized-event-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 11 {
		t.Fatalf("corpus=%+v err=%v", corpus, err)
	}
	for _, denial := range corpus.Cases {
		mutate, exists := mutations[denial.Name]
		if !exists {
			t.Fatalf("missing mutation %s", denial.Name)
		}
		if _, err := Decode(context.Background(), mutate(append([]byte(nil), base...))); Code(err) != InvalidInput || Reason(err) != denial.Reason {
			t.Fatalf("%s code=%s reason=%s err=%v", denial.Name, Code(err), Reason(err), err)
		}
	}
}

func TestChangedFieldsRequireNewSectionAndTransformationDigests(t *testing.T) {
	validated := decodeFixture(t, "event.canonical.json")
	value := validated.Value()
	value.Original.Fields = json.RawMessage(`{"event":{"code":"4625"},"host":{"name":"ws-01"},"message":"changed","winlog":{"event_id":4625}}`)
	value.Original.FieldsDigest = digestBytes(value.Original.Fields)
	if _, err := Decode(context.Background(), marshal(t, value)); Reason(err) != "transformation_digest" {
		t.Fatalf("changed source with stale transform err=%v", err)
	}
	digest, err := TransformationDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Normalization.TransformationDigest = digest
	if _, err := Decode(context.Background(), marshal(t, value)); err != nil {
		t.Fatalf("rebound transformation: %v", err)
	}
}

func TestExplicitNullECSAndUnmappedCoverage(t *testing.T) {
	value := decodeFixture(t, "event.canonical.json").Value()
	value.ECS = nil
	value.Normalization.Coverage = "partial"
	value.Normalization.UnmappedVendorPaths = []string{"winlog.event_id"}
	digest, err := TransformationDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Normalization.TransformationDigest = digest
	validated, err := Decode(context.Background(), marshal(t, value))
	if err != nil || validated.Value().ECS != nil {
		t.Fatalf("explicit null ECS err=%v", err)
	}
}

func TestFixedDecimalValuesRemainLossless(t *testing.T) {
	value := decodeFixture(t, "event.canonical.json").Value()
	value.Original.Fields = json.RawMessage(`{"event":{"code":"4624"},"score":0.125}`)
	value.Original.FieldsDigest = digestBytes(value.Original.Fields)
	value.OCSF.Event = json.RawMessage(`{"activity_id":1,"category_uid":3,"class_uid":3002,"confidence_score":0.875,"metadata":{"product":{"name":"COH fixture"},"version":"1.9.0"},"severity_id":1,"time":1787798400000,"type_uid":300201}`)
	value.OCSF.EventDigest = digestBytes(value.OCSF.Event)
	digest, err := TransformationDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.Normalization.TransformationDigest = digest
	validated, err := Decode(context.Background(), marshal(t, value))
	if err != nil || !bytes.Contains(validated.Value().OCSF.Event, []byte(`"confidence_score":0.875`)) ||
		!bytes.Contains(validated.Value().Original.Fields, []byte(`"score":0.125`)) {
		t.Fatalf("fixed decimals were not retained: %v", err)
	}
}

func TestCancellationTimeoutAndRecovery(t *testing.T) {
	input := readFixture(t, "valid", "event.canonical.json")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Decode(canceled, input); Code(err) != Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := Decode(deadline, input); Code(err) != Timeout {
		t.Fatalf("timeout err=%v", err)
	}
	if _, err := Decode(context.Background(), input); err != nil {
		t.Fatalf("recovery err=%v", err)
	}
}

func TestEvidenceResolverBindsExactCOHE10Identity(t *testing.T) {
	validated := decodeFixture(t, "event.canonical.json")
	value := validated.Value()
	binding := SourceBinding{Case: value.Case, Artifact: value.Lineage.RawArtifact, ManifestDigest: value.Lineage.RawManifestDigest,
		IngestReceiptDigest: value.Lineage.IngestReceiptDigest, SourceProvenanceDigest: value.Lineage.SourceProvenanceDigest}
	if err := VerifyEvidence(context.Background(), validated, resolverStub{resolved: ResolvedSource{Binding: binding}}); err != nil {
		t.Fatal(err)
	}
	changed := binding
	changed.Case.TenantID = "0198e300-1000-7000-8000-000000000099"
	if err := VerifyEvidence(context.Background(), validated, resolverStub{resolved: ResolvedSource{Binding: changed}}); Code(err) != Conflict {
		t.Fatalf("scope substitution err=%v", err)
	}
	if err := VerifyEvidence(context.Background(), validated, resolverStub{err: errors.New("offline")}); Code(err) != Unavailable {
		t.Fatalf("unavailable err=%v", err)
	}
}

func TestBoundedDatasetReaderEnforcesPageAndRecordBindings(t *testing.T) {
	fixture := bytes.TrimSpace(readFixture(t, "valid", "dataset-event.canonical.json"))
	value := decodeFixture(t, "dataset-event.canonical.json").Value()
	request := DatasetReadRequest{Case: value.Case, Dataset: *value.Dataset}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wanted := DatasetPage{Records: [][]byte{fixture}, Complete: true, RowsRead: 1, BytesRead: uint64(len(fixture))}
	page, err := ReadDatasetPage(ctx, datasetReaderStub{page: wanted}, request)
	if err != nil || !page.Complete() || page.RowsRead() != 1 || page.BytesRead() != uint64(len(fixture)) || len(page.Records()) != 1 {
		t.Fatalf("valid page=%+v err=%v", page, err)
	}

	overflow := wanted
	overflow.RowsRead = request.Dataset.AccessProfile.MaxRows + 1
	if _, err := ReadDatasetPage(ctx, datasetReaderStub{page: overflow}, request); Code(err) != Conflict || Reason(err) != "dataset_page_bounds" {
		t.Fatalf("row overflow err=%v", err)
	}
	wrongRecord := wanted
	wrongRecord.Records = [][]byte{bytes.TrimSpace(readFixture(t, "valid", "event.canonical.json"))}
	wrongRecord.BytesRead = uint64(len(wrongRecord.Records[0]))
	if _, err := ReadDatasetPage(ctx, datasetReaderStub{page: wrongRecord}, request); Code(err) != Conflict || Reason(err) != "dataset_record_binding" {
		t.Fatalf("record substitution err=%v", err)
	}
	if _, err := ReadDatasetPage(context.Background(), datasetReaderStub{page: wanted}, request); Code(err) != InvalidInput || Reason(err) != "dataset_deadline" {
		t.Fatalf("unbounded deadline err=%v", err)
	}
}

func TestPublicDatasetBoundaryHasNoDirectAccessSurface(t *testing.T) {
	for _, value := range []any{Dataset{}, DatasetReadRequest{}, SourceBinding{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := strings.ToLower(typeOf.Field(index).Name)
			for _, forbidden := range []string{"path", "url", "sql", "http", "client", "connector", "credential", "secret", "key"} {
				if strings.Contains(name, forbidden) && name != "partitionkeys" {
					t.Fatalf("%s exposes %s", typeOf.Name(), name)
				}
			}
		}
	}
	interfaceType := reflect.TypeOf((*DatasetReader)(nil)).Elem()
	if interfaceType.NumMethod() != 1 || interfaceType.Method(0).Name != "ReadPage" {
		t.Fatalf("dataset reader surface=%v", interfaceType)
	}
}

func FuzzDecodeNeverAcceptsChangedCanonicalFixture(f *testing.F) {
	fixture := bytes.TrimSpace(readFixture(f, "valid", "event.canonical.json"))
	f.Add(fixture)
	f.Fuzz(func(t *testing.T, input []byte) {
		validated, err := Decode(context.Background(), input)
		if err == nil {
			again, roundTripErr := Decode(context.Background(), validated.CanonicalBytes())
			if roundTripErr != nil || again.Digest() != validated.Digest() {
				t.Fatalf("accepted value did not recover: %v", roundTripErr)
			}
		}
	})
}

type resolverStub struct {
	resolved ResolvedSource
	err      error
}

type datasetReaderStub struct {
	page DatasetPage
	err  error
}

func (stub datasetReaderStub) ReadPage(context.Context, DatasetReadRequest) (DatasetPage, error) {
	return stub.page, stub.err
}

func (stub resolverStub) ResolveEvidence(context.Context, SourceBinding) (ResolvedSource, error) {
	return stub.resolved, stub.err
}

func decodeFixture(t *testing.T, name string) ValidatedEnvelope {
	t.Helper()
	value, err := Decode(context.Background(), readFixture(t, "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func readFixture(t testing.TB, parts ...string) []byte {
	t.Helper()
	pathParts := append([]string{"..", "..", "..", "contracts", "normalization", "v1", "fixtures"}, parts...)
	value, err := os.ReadFile(filepath.Join(pathParts...))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func marshal(t *testing.T, value Envelope) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mutateAfter(input []byte, anchor, oldValue, newValue string) []byte {
	index := bytes.Index(input, []byte(anchor))
	if index < 0 {
		return input
	}
	result := append([]byte(nil), input...)
	tail := bytes.Replace(result[index:], []byte(oldValue), []byte(newValue), 1)
	return append(result[:index], tail...)
}
