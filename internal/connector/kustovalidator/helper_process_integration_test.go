package kustovalidator

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPinnedHelperProcessContract(t *testing.T) {
	helper := os.Getenv("COH_KUSTO_HELPER")
	if helper == "" {
		t.Skip("COH_KUSTO_HELPER is not set")
	}
	requestBytes := readFixture(t, "helper-request.json")
	request, err := DecodeHelperRequest(requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	runPinnedHelper(t, helper, request)
	unicode := request
	unicode.Query = `SecurityEvent | where Computer == "München<&>" | project Computer`
	unicode.QueryDigest = QueryDigest(unicode.Query)
	unicode.RequestDigest = HelperRequestDigest(unicode)
	runPinnedHelper(t, helper, unicode)
}

func runPinnedHelper(t *testing.T, helper string, request HelperRequest) {
	t.Helper()
	requestBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := json.Marshal(map[string]string{"request_chunk_00": string(requestBytes)})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helper)
	command.Stdin = bytes.NewReader(transport)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("helper failed: %v stderr=%q", err, stderr.String())
	}
	response, err := DecodeHelperResponse(output)
	if err != nil {
		t.Fatalf("Go denied helper response: %v\n%s", err, output)
	}
	if err := ValidateHelperExchange(request, response); err != nil {
		t.Fatalf("helper exchange denied: %v", err)
	}
	if response.Outcome != "accepted" || response.TerminalTake != request.RequestedRows ||
		!strings.HasSuffix(response.CanonicalKQL, " | take 500") {
		t.Fatalf("unexpected bounded response: %+v", response)
	}
}
