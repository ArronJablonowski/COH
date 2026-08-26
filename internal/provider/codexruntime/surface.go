package codexruntime

import (
	"context"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	AdapterVersion       = "1.0.0"
	RuntimeVersion       = "0.145.0"
	ProtocolVersion      = "app-server.v2/821c237d"
	RuntimeDigest        = "sha256:1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590"
	ProtocolDigest       = "sha256:821c237d2ed4c9b736c82cdd5f302e881be1d5994abb3959060b795d4dd442ce"
	maximumFrameBytes    = 2 << 20
	maximumTraceBytes    = 16 << 20
	maximumResponseBytes = maximumTraceBytes
	maximumEvents        = 4096
)

type Config struct {
	Capability     providercontract.ValidatedCapability
	Qualifications *providercontract.QualificationRegistry
	Schemas        SchemaResolver
	Tools          ToolBroker
	Reasoning      ReasoningStore
	Factory        AppServerFactory
	Batch          BatchRunner
	Clock          func() time.Time
	Workspace      string
}

type SchemaDocument struct {
	Digest string
	JSON   json.RawMessage
}
type SchemaResolver interface {
	Resolve(context.Context, string) (SchemaDocument, error)
}

type ToolCall struct {
	RequestID, AttemptID, CallID, Name, InputSchemaDigest, OutputSchemaDigest string
	Arguments                                                                 json.RawMessage
}
type ToolResult struct {
	Outcome      string
	Value        json.RawMessage
	ResultDigest string
}
type ToolBroker interface {
	Call(context.Context, ToolCall) (ToolResult, error)
}
type ReasoningStore interface {
	Put(context.Context, string, string, []byte) error
}

type RPCTransport interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

type LaunchObservation struct {
	RuntimeVersion      string
	RuntimeDigest       string
	ProtocolDigest      string
	Model               string
	ModelRevision       string
	Workspace           string
	Transport           string
	Sandbox             string
	ApprovalPolicy      string
	NetworkMode         string
	ConfigDigest        string
	EnvironmentDigest   string
	CredentialMode      string
	ExperimentalSurface string
	CodexHome           string
	ConfigMode          string
	RulesMode           string
	HooksMode           string
	MCPMode             string
	WebSearchMode       string
	MutationMode        string
	EnvironmentMode     string
}

type AppServerFactory interface {
	Open(context.Context) (RPCTransport, LaunchObservation, error)
}

type BatchInvocation struct {
	Argv               []string
	Environment        map[string]string
	WorkingDirectory   string
	Stdin              []byte
	OutputSchema       json.RawMessage
	MaximumOutputBytes uint64
	Deadline           time.Time
}
type BatchResult struct {
	JSONL       []byte
	Stderr      []byte
	ExitCode    int
	Observation LaunchObservation
}
type BatchRunner interface {
	Run(context.Context, BatchInvocation) (BatchResult, error)
}

func EndpointIdentityDigest(mode, workspace string) string {
	return digest("COH-CODEX-RUNTIME-ENDPOINT-V1\x00", []byte(mode+"\x00"+workspace+"\x00"+ProtocolVersion))
}
