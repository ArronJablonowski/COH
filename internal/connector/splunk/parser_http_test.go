package splunk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func TestHTTPParserPreflightUsesExactV2FailClosedParameters(t *testing.T) {
	t.Parallel()
	canonical := `search index=security src_ip = "192.0.2.1" | fields _time, src_ip | sort 0 -_time | head 100`
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/services/search/v2/parser" || request.URL.RawQuery != "" {
			t.Errorf("request=%s %s", request.Method, request.URL.String())
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		wants := map[string]string{"output_mode": "json", "q": canonical, "parse_only": "true",
			"enable_lookups": "false", "reload_macros": "false"}
		if len(request.PostForm) != len(wants) {
			t.Errorf("form=%v", request.PostForm)
		}
		for key, want := range wants {
			if request.PostForm.Get(key) != want || len(request.PostForm[key]) != 1 {
				t.Errorf("%s=%v want %q", key, request.PostForm[key], want)
			}
		}
		writeJSON(t, writer, parserVendorResponse([]string{"search", "fields", "sort", "head"}))
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)
	client, err := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	result, receipt, err := client.ParserPreflight(context.Background(), ParserRequest{
		Binding: splunkTestBinding("splunk.parser"), CanonicalSPL: canonical})
	if err != nil || !slices.Equal(result.Commands, []string{"search", "fields", "sort", "head"}) ||
		receipt.TransportDigest != config.TransportIdentityDigest {
		t.Fatalf("result=%+v receipt=%+v err=%v", result, receipt, err)
	}
}

func TestHTTPParserPreflightRejectsUnknownResponseShape(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response := parserVendorResponse([]string{"search"})
		response["unexpected"] = true
		writeJSON(t, writer, response)
	}))
	defer server.Close()
	config, roots := splunkHTTPTestConfig(t, server)
	client, _ := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
	_, _, err := client.ParserPreflight(context.Background(), ParserRequest{Binding: splunkTestBinding("splunk.parser"),
		CanonicalSPL: "search index=security | fields _time | sort 0 -_time | head 1"})
	if err == nil || queryconnector.Reason(err) != "splunk_parser_response_invalid" {
		t.Fatalf("err=%v", err)
	}
}

func TestQualifiedParserResponseFixtures(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"splunk-9.4", "splunk-10.0"} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			fixture, err := os.ReadFile("testdata/" + version + "/parser-response.json")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(fixture)
			}))
			defer server.Close()
			config, roots := splunkHTTPTestConfig(t, server)
			client, _ := NewHTTPClient(config, &splunkCredentialStub{token: []byte("token"), decision: splunkTestDigest("8")}, roots)
			result, _, err := client.ParserPreflight(context.Background(), ParserRequest{Binding: splunkTestBinding("splunk.parser"),
				CanonicalSPL: `search index=security src_ip="192.0.2.1" | fields _time, src_ip | sort 0 -_time | head 100`})
			if err != nil || !slices.Equal(result.Commands, []string{"search", "fields", "sort", "head"}) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func parserVendorResponse(commands []string) map[string]any {
	items := make([]map[string]any, 0, len(commands))
	for _, command := range commands {
		items = append(items, map[string]any{"command": command, "rawargs": "", "pipeline": "streaming",
			"args": map[string]any{"search": []string{""}}, "isGenerating": command == "search", "streamType": "SP_STREAM"})
	}
	return map[string]any{"remoteSearch": "litsearch", "remoteTimeOrdered": true, "eventsSearch": "search index=security",
		"eventsTimeOrdered": true, "eventsStreaming": true, "reportsSearch": "", "commands": items}
}
