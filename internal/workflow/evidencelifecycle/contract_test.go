package evidencelifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestPublishedEvidenceLifecycleSchemaIsStrictAndVersioned(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "evidence-lifecycle", "v1", "evidence-lifecycle.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	definitions, ok := document["$defs"].(map[string]any)
	if !ok || document["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("evidence lifecycle schema version or definitions missing")
	}
	for _, name := range []string{"command", "export_manifest", "detached_signature", "package_header",
		"import_verification", "authorization_request", "decision", "progress",
		"disposition_attestation", "record", "receipt"} {
		definition, found := definitions[name].(map[string]any)
		if !found || definition["additionalProperties"] != false {
			t.Fatalf("%s is not closed", name)
		}
	}
	assertStringEnum(t, definitions, "operation", []string{"export", "import", "place_hold", "release_hold", "delete"})
	if packageHeader := definitions["package_header"].(map[string]any); packageHeader["additionalProperties"] != false {
		t.Fatal("package header is not closed")
	}
}

func TestEvidenceLifecycleSchemaAndGoRecordsStaySynchronized(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "evidence-lifecycle", "v1", "evidence-lifecycle.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	definitions := document["$defs"].(map[string]any)
	for name, value := range map[string]any{
		"command": Command{}, "export_manifest": ExportManifest{}, "detached_signature": DetachedSignature{},
		"package_header": PackageHeader{}, "import_verification": ImportVerification{},
		"authorization_request": AuthorizationRequest{}, "decision": Decision{}, "progress": Progress{},
		"disposition_attestation": DispositionAttestation{}, "record": Record{}, "receipt": Receipt{},
		"case": domain.CaseRef{}, "artifact": domain.ArtifactRef{}, "evidence_reference": EvidenceReference{},
		"custody_head": CustodyHead{}, "package_limits": PackageLimits{}, "component": Component{},
		"manifest_artifact": ManifestArtifact{}, "artifact_progress": ArtifactProgress{},
		"disposition_object": DispositionObject{},
	} {
		definition := definitions[name].(map[string]any)
		properties := definition["properties"].(map[string]any)
		required := definition["required"].([]any)
		goFields := reflect.TypeOf(value)
		if len(properties) != goFields.NumField() || len(required) != goFields.NumField() {
			t.Fatalf("%s schema=%d required=%d Go=%d", name, len(properties), len(required), goFields.NumField())
		}
		for index := 0; index < goFields.NumField(); index++ {
			field := snakeName(goFields.Field(index).Name)
			if _, found := properties[field]; !found || !containsRequired(required, field) {
				t.Fatalf("%s.%s is not a required schema property", name, field)
			}
		}
	}
}

func TestEvidenceLifecyclePortsAreNarrow(t *testing.T) {
	ports := []struct {
		typeOf  reflect.Type
		methods []string
	}{
		{reflect.TypeOf((*Authority)(nil)).Elem(), []string{"AuthorizeEvidenceLifecycle"}},
		{reflect.TypeOf((*CaseStore)(nil)).Elem(), []string{"HasIncompleteHoldRelease", "LoadCase", "ResolveLifecycleReceipt"}},
		{reflect.TypeOf((*CaseLifecycle)(nil)).Elem(), []string{"ApplyCaseOperation"}},
		{reflect.TypeOf((*EvidenceResolver)(nil)).Elem(), []string{"ResolveEvidenceSet"}},
		{reflect.TypeOf((*RedactionResolver)(nil)).Elem(), []string{"VerifyRedactionReceipts"}},
		{reflect.TypeOf((*Custody)(nil)).Elem(), []string{"LoadCustodyHead", "RecordLifecycle", "VerifyLifecycle"}},
		{reflect.TypeOf((*Signer)(nil)).Elem(), []string{"SignManifest"}},
		{reflect.TypeOf((*SignatureVerifier)(nil)).Elem(), []string{"VerifyDetachedSignature"}},
		{reflect.TypeOf((*PackageWriter)(nil)).Elem(), []string{"BuildPackage", "RecoverPackage", "VerifyPackage"}},
		{reflect.TypeOf((*PackageReader)(nil)).Elem(), []string{"VerifyImport"}},
		{reflect.TypeOf((*Publisher)(nil)).Elem(), []string{"PublishImport"}},
		{reflect.TypeOf((*Disposer)(nil)).Elem(), []string{"DisposeEvidence", "RecoverDisposition"}},
		{reflect.TypeOf((*Store)(nil)).Elem(), []string{"Advance", "Commit", "LoadProgress", "Recover"}},
		{reflect.TypeOf((*Auditor)(nil)).Elem(), []string{"AppendLifecycleEvent", "VerifyLifecycleEvent"}},
		{reflect.TypeOf((*Clock)(nil)).Elem(), []string{"Now"}},
	}
	for _, port := range ports {
		actual := make([]string, port.typeOf.NumMethod())
		for index := range actual {
			actual[index] = port.typeOf.Method(index).Name
		}
		sort.Strings(port.methods)
		if !reflect.DeepEqual(actual, port.methods) {
			t.Fatalf("%s methods=%v want=%v", port.typeOf, actual, port.methods)
		}
	}
}

func TestEvidenceLifecycleRecordsExposeNoAuthorityOrUnsafeSurface(t *testing.T) {
	for _, value := range []any{Command{}, ExportManifest{}, DetachedSignature{}, PackageHeader{},
		ImportVerification{}, AuthorizationRequest{}, Decision{}, Progress{}, DispositionAttestation{},
		Record{}, Receipt{}, PackageLimits{}, EvidenceReference{}, ManifestArtifact{}, Component{},
		CaseSnapshot{}, LifecycleRequest{}, LifecycleProof{}, VerifiedEvidenceSet{}, RedactionProof{},
		CustodyRequest{}, CustodyProof{}, CustodyVerification{}, QuarantinedPackage{}, VerifiedImport{},
		PublishedImport{}, DispositionRequest{}, SignRequest{}, VerifySignatureRequest{}, PackageBuildRequest{},
		ImportRequest{}, ImportPublicationRequest{}, Result{}} {
		assertSafeLifecycleType(t, reflect.TypeOf(value), map[reflect.Type]bool{})
	}
}

func assertStringEnum(t *testing.T, definitions map[string]any, name string, want []string) {
	t.Helper()
	values := definitions[name].(map[string]any)["enum"].([]any)
	actual := make([]string, len(values))
	for index := range values {
		actual[index] = values[index].(string)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("%s=%v want=%v", name, actual, want)
	}
}

func containsRequired(values []any, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func assertSafeLifecycleType(t *testing.T, value reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name := strings.ToLower(field.Name)
		for _, forbidden := range []string{"credential", "secret", "policysource", "connector", "executor",
			"provider", "callback", "client", "path", "url", "privatekey", "commandline"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("%s.%s exposes forbidden surface", value, field.Name)
			}
		}
		if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Chan || field.Type.Kind() == reflect.Map ||
			field.Type.Kind() == reflect.Interface {
			t.Fatalf("%s.%s exposes executable or generic surface", value, field.Name)
		}
		assertSafeLifecycleType(t, field.Type, seen)
	}
}
