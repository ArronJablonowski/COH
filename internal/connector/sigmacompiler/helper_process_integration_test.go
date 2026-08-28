package sigmacompiler

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPinnedHelperProcessContract(t *testing.T) {
	helper := os.Getenv("COH_PYSIGMA_HELPER")
	if helper == "" {
		t.Skip("COH_PYSIGMA_HELPER is not configured")
	}
	requestInput := readContractFixture(t, "compile-request.json")
	request, err := DecodeCompileRequest(requestInput)
	if err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, helper)
	command.Stdin = bytes.NewReader(requestInput)
	var standardError bytes.Buffer
	command.Stderr = &standardError
	responseInput, err := command.Output()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("helper execution failed: err=%v context=%v", err, ctx.Err())
	}
	if standardError.Len() != 0 {
		t.Fatal("helper emitted standard error")
	}
	response, err := DecodeCompileResponse(responseInput)
	if err != nil {
		t.Fatalf("decode helper response: %v", err)
	}
	if err := ValidateExchange(request, response); err != nil {
		t.Fatalf("validate helper exchange: %v", err)
	}
	if response.Outcome != "compiled_untrusted" || !strings.Contains(response.NativeQuery, request.Mapping.TargetResource) {
		t.Fatal("helper did not return one resource-bound untrusted query")
	}
}
