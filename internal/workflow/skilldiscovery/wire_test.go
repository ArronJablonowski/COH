package skilldiscovery

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPublishedDiscoveryRequestsStrictlyRoundTrip(t *testing.T) {
	fixture := newTestFixture(t)
	search := fixture.search()
	searchBytes, searchDigest, err := CanonicalSearchRequest(search)
	if err != nil {
		t.Fatal(err)
	}
	decodedSearch, err := DecodeSearchRequest(searchBytes)
	if err != nil || !reflect.DeepEqual(decodedSearch, search) || !digestPattern.MatchString(searchDigest) {
		t.Fatalf("search round trip failed: %#v %v", decodedSearch, err)
	}
	detail := fixture.detail("alpha_skill")
	detailBytes, _, err := CanonicalDetailRequest(detail)
	if err != nil {
		t.Fatal(err)
	}
	decodedDetail, err := DecodeDetailRequest(detailBytes)
	if err != nil || !reflect.DeepEqual(decodedDetail, detail) {
		t.Fatalf("detail round trip failed: %#v %v", decodedDetail, err)
	}
	resource := fixture.resource("alpha_skill")
	resourceBytes, _, err := CanonicalResourceRequest(resource)
	if err != nil {
		t.Fatal(err)
	}
	decodedResource, err := DecodeResourceRequest(resourceBytes)
	if err != nil || !reflect.DeepEqual(decodedResource, resource) {
		t.Fatalf("resource round trip failed: %#v %v", decodedResource, err)
	}
}

func TestDiscoveryWireRejectsUnknownMissingDuplicateTrailingAndNoncanonical(t *testing.T) {
	fixture := newTestFixture(t)
	input, _, err := CanonicalSearchRequest(fixture.search())
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(input, []byte(`"actor_id":`), []byte(`"unknown":"x","actor_id":`), 1)
	missing := bytes.Replace(input, []byte(`"query":"",`), nil, 1)
	duplicate := bytes.Replace(input, []byte(`"query":"",`), []byte(`"query":"","query":"",`), 1)
	trailing := append(append([]byte(nil), input...), []byte(` {}`)...)
	noncanonical := bytes.Replace(input, []byte(`.000000000Z`), []byte(`Z`), 1)
	for name, malformed := range map[string][]byte{"unknown": unknown, "missing": missing,
		"duplicate": duplicate, "trailing": trailing, "noncanonical": noncanonical} {
		if _, err := DecodeSearchRequest(malformed); err == nil {
			t.Fatalf("%s input accepted: %s", name, malformed)
		}
	}
}
