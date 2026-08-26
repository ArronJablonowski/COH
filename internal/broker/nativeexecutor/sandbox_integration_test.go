//go:build darwin

package nativeexecutor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestProcessSandboxExecutesWithoutDockerOrAmbientEnvironment(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "coh-native-limit")
	testTool := filepath.Join(root, "native-echo")
	repositoryRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate go toolchain: %v", err)
	}
	command := exec.Command(goBinary, "build", "-trimpath", "-o", helper, "./cmd/coh-native-limit")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v: %s", err, output)
	}
	command = exec.Command(goBinary, "build", "-trimpath", "-o", testTool, "./internal/broker/nativeexecutor/testdata/native_echo")
	command.Dir = repositoryRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build test tool: %v: %s", err, output)
	}
	helperBytes, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	preparer, err := NewFileArtifactPreparer(root)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := NewProcessSandbox(helper, digestBytes(helperBytes), root, preparer)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := preparer.Prepare(context.Background(), testTool, fileDigest(t, testTool), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer tool.Cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := sandbox.Execute(ctx, Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
		Arguments: []string{"echo"}, Environment: []string{"LANG=C"},
		Input: []byte("bounded input\n"), Limits: toolLimits(),
		Network: toolregistryNetworkNone()})
	if err != nil {
		t.Fatalf("Execute() error=%v stderr=%s", err, result.StandardError)
	}
	if result.ExitCode != 0 || string(result.StandardOutput) != "bounded input\n" {
		t.Fatalf("result=%+v", result)
	}
	t.Run("clean environment", func(t *testing.T) {
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"environment"}, Environment: []string{"LANG=C"}, Limits: toolLimits(), Network: toolregistryNetworkNone()})
		if err != nil || string(result.StandardOutput) != "LANG=C\n" {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("network denied", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"connect", listener.Addr().String()}, Limits: toolLimits(), Network: toolregistryNetworkNone()})
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("network result=%+v error=%v", result, err)
		}
	})
	t.Run("filesystem escape denied", func(t *testing.T) {
		escape := filepath.Join(t.TempDir(), "escape")
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"write", escape}, Limits: toolLimits(), Network: toolregistryNetworkNone()})
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("filesystem result=%+v error=%v", result, err)
		}
		if _, err := os.Stat(escape); !os.IsNotExist(err) {
			t.Fatalf("sandbox wrote outside working directory: %v", err)
		}
	})
	t.Run("output bounded", func(t *testing.T) {
		limits := toolLimits()
		limits.OutputBytes = 16
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"output", "4096"}, Limits: limits, Network: toolregistryNetworkNone()})
		if Code(err) != Denied || Reason(err) != "output_limit" || len(result.StandardOutput) != 16 || !result.OutputTruncated {
			t.Fatalf("output result=%+v error=%v", result, err)
		}
	})
	t.Run("cancellation kills process group", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		result, err := sandbox.Execute(ctx, Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"sleep"}, Limits: toolLimits(), Network: toolregistryNetworkNone()})
		if Code(err) != Timeout || result.ExitCode != -1 {
			t.Fatalf("cancel result=%+v error=%v", result, err)
		}
	})
	t.Run("process count bounded", func(t *testing.T) {
		limits := toolLimits()
		limits.ProcessCount = 1
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"children"}, Limits: limits, Network: toolregistryNetworkNone()})
		if Code(err) != Denied || Reason(err) != "process_limit" || result.ExitCode != -1 {
			t.Fatalf("process result=%+v error=%v", result, err)
		}
	})
	t.Run("resident memory bounded", func(t *testing.T) {
		limits := toolLimits()
		limits.MemoryBytes = 32 << 20
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"memory"}, Limits: limits, Network: toolregistryNetworkNone()})
		if Code(err) != Denied || Reason(err) != "memory_limit" || result.ExitCode != -1 {
			t.Fatalf("memory result=%+v error=%v", result, err)
		}
	})
	t.Run("ephemeral storage bounded", func(t *testing.T) {
		limits := toolLimits()
		limits.EphemeralStorageBytes = 64 << 10
		result, err := sandbox.Execute(context.Background(), Plan{ExecutablePath: tool.Path, ArtifactDigest: tool.Digest,
			Arguments: []string{"storage"}, Limits: limits, Network: toolregistryNetworkNone()})
		if Code(err) != Denied || Reason(err) != "ephemeral_storage_limit" || result.ExitCode != -1 {
			t.Fatalf("storage result=%+v error=%v", result, err)
		}
	})
	t.Run("executor end to end", func(t *testing.T) {
		toolReference := toolregistry.ToolReference{Name: "fixture.echo", Version: "1.0.0", ArtifactDigest: fileDigest(t, testTool)}
		registry, publisher := signedRegistry(t, toolReference)
		executor, err := New(registry, testAuthorizer(), preparer, sandbox,
			fixedClock{time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)}, []Registration{{Tool: toolReference,
				Operation: "execute", ExecutablePath: testTool, FixedArguments: []string{"echo"},
				FixedEnvironment: []EnvironmentVariable{{Name: "LANG", Value: "C"}}}})
		if err != nil {
			t.Fatal(err)
		}
		request := testRequest()
		request.Tool = toolReference
		request.Publisher = publisher
		request.Inputs = map[string]InputValue{"message": {Kind: "string", String: "hello"}}
		result, err := executor.Execute(context.Background(), request)
		if err != nil || string(result.StandardOutput) != `{"message":"hello"}` ||
			result.Provenance.AuthorizationID == "" || result.Provenance.PolicyDecisionDigest == "" ||
			result.Provenance.ArtifactDigest != toolReference.ArtifactDigest {
			t.Fatalf("result=%+v error=%v", result, err)
		}
		revoked := request
		revoked.AttemptID = "0198d6c4-5555-7555-8555-555555555556"
		revoked.Publisher.Active = false
		if _, err := executor.Execute(context.Background(), revoked); Code(err) != Denied ||
			Reason(err) != "registry_publisher_authority" {
			t.Fatalf("revoked publisher error=%v", err)
		}
		original, err := os.ReadFile(testTool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testTool, append(original, 'x'), 0o500); err != nil {
			t.Fatal(err)
		}
		drifted := request
		drifted.AttemptID = "0198d6c4-5555-7555-8555-555555555557"
		if _, err := executor.Execute(context.Background(), drifted); Code(err) != Denied ||
			Reason(err) != "artifact_digest_mismatch" {
			t.Fatalf("artifact drift error=%v", err)
		}
	})
}

func signedRegistry(t *testing.T, tool toolregistry.ToolReference) (*toolregistry.Registry, toolregistry.PublisherAuthority) {
	t.Helper()
	now := time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)
	manifest := toolregistry.Manifest{SchemaVersion: toolregistry.ManifestSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, ManifestID: "0198d6c4-1111-7111-8111-111111111111",
		ToolName: tool.Name, ToolVersion: tool.Version, ArtifactDigest: tool.ArtifactDigest, MaximumActionTier: "T1",
		PublisherID: "0198d6c4-2222-7222-8222-222222222222", ReviewID: "0198d6c4-3333-7333-8333-333333333333",
		ReviewRevision: 1, ReviewDecision: "approved",
		ReviewerActorIDs: []string{"0198d6c4-4444-7444-8444-444444444444"}, ThreatModelDigest: inputDigest,
		ReviewedAt: now.Add(-time.Hour).Format("2006-01-02T15:04:05.000000000Z"),
		ValidFrom:  now.Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z"),
		ValidUntil: now.Add(time.Hour).Format("2006-01-02T15:04:05.000000000Z"),
		Operations: []toolregistry.Operation{{Name: "execute", InputSchemaVersion: "coh.tool-input/v1",
			InputFields:        []toolregistry.InputField{{Name: "message", Type: "string", Required: true, MaximumBytes: 64, Enum: []string{}}},
			BaselineActionTier: "T1", MaximumActionTier: "T1", IsolationClass: "native_restricted",
			CredentialClasses: []string{"none"}, ResourceLimits: toolLimits(), NetworkPolicy: toolregistryNetworkNone(),
			CancellationMode: "cooperative", RetryMode: "safe"}}}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := toolregistry.Decode(context.Background(), manifestJSON)
	if err != nil {
		t.Fatalf("Decode() error=%v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	authority := toolregistry.PublisherAuthority{PublisherID: manifest.PublisherID, KeyID: "publisher.primary",
		KeyRevision: 1, ApprovalRevision: 1, Active: true, Approved: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(privateKey, append([]byte(toolregistry.SignatureDomain), validated.CanonicalBytes()...))
	envelope := toolregistry.Envelope{SchemaVersion: toolregistry.EnvelopeSchemaVersion,
		ContractVersion: toolregistry.ContractVersion, Manifest: manifest, ManifestDigest: validated.Digest,
		PublisherID: authority.PublisherID, PublisherKeyID: authority.KeyID, PublisherKeyRevision: authority.KeyRevision,
		SignatureAlgorithm: toolregistry.SignatureAlgorithm, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.NewRegistry(fixedClock{now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Admit(context.Background(), envelopeJSON, authority); err != nil {
		t.Fatalf("Admit() error=%v", err)
	}
	return registry, authority
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digestBytes(data)
}

func toolLimits() toolregistry.ResourceLimits {
	return toolregistry.ResourceLimits{WallTimeMilliseconds: 15_000, CPUMilliseconds: 2000,
		MemoryBytes: 256 << 20, OutputBytes: 1 << 20, EphemeralStorageBytes: 4 << 20,
		ProcessCount: 4, OpenFileCount: 64}
}

func toolregistryNetworkNone() toolregistry.NetworkPolicy {
	return toolregistry.NetworkPolicy{Mode: "none", DNSMode: "none"}
}
