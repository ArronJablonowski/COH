package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordedLifecycleFixturesConformAcrossQualifiedMinors(t *testing.T) {
	manifest, err := os.ReadFile("testdata/lifecycle-fixture-manifest.json")
	if err != nil || !json.Valid(manifest) {
		t.Fatalf("manifest err=%v", err)
	}
	for _, version := range []string{"splunk-9.4", "splunk-10.0"} {
		t.Run(version, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				name, status := "", http.StatusOK
				switch request.URL.Path {
				case "/services/search/jobs":
					name, status = "search-create.json", http.StatusCreated
				case "/services/search/jobs/" + lifecycleTestSID:
					name = "search-status-done.json"
				case "/services/search/jobs/" + lifecycleTestSID + "/results":
					name = "search-results.json"
				case "/services/search/jobs/" + lifecycleTestSID + "/control":
					name = "search-cancel.json"
				default:
					http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
					return
				}
				input, readErr := os.ReadFile(filepath.Join("testdata", version, name))
				if readErr != nil {
					t.Error(readErr)
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(status)
				_, _ = writer.Write(input)
			}))
			defer server.Close()
			config, roots := splunkHTTPTestConfig(t, server)
			client, clientErr := NewHTTPClient(config,
				&splunkCredentialStub{token: []byte("broker-token"), decision: splunkTestDigest("8")}, roots)
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			plan := lifecycleTestPlan(t)
			created, _, createErr := client.CreateSearch(context.Background(), SearchCreateRequest{
				Binding: splunkTestBinding("splunk.search.create"), Plan: plan})
			if createErr != nil || created.SID != lifecycleTestSID {
				t.Fatalf("create=%+v err=%v", created, createErr)
			}
			status, _, statusErr := client.SearchStatus(context.Background(), SearchStatusRequest{
				Binding: splunkTestBinding("splunk.search.status"), SID: created.SID})
			if statusErr != nil || status.State != "DONE" || status.ResultCount != 2 {
				t.Fatalf("status=%+v err=%v", status, statusErr)
			}
			results, _, resultErr := client.SearchResults(context.Background(), SearchResultsRequest{
				Binding: splunkTestBinding("splunk.search.results"), SID: created.SID, Count: 2, Total: 2, Plan: plan})
			if resultErr != nil || len(results.Results) != 2 {
				t.Fatalf("results=%+v err=%v", results, resultErr)
			}
			canceled, _, cancelErr := client.CancelSearch(context.Background(), SearchCancelRequest{
				Binding: splunkTestBinding("splunk.search.cancel"), SID: created.SID})
			if cancelErr != nil || !canceled.Acknowledged {
				t.Fatalf("canceled=%+v err=%v", canceled, cancelErr)
			}
		})
	}
}
