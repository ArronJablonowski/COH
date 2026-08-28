package sigmacompiler

import (
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const (
	NativeToolName      = "sigma.compiler"
	NativeToolVersion   = "1.0.0"
	NativeOperationName = "compile"
	maximumChunkBytes   = 61_440
	maximumChunkCount   = 8
)

// NativeOperation is the only execution surface authorized for the signed
// credentialless helper. Its input is the closed CompileRequest protocol.
func NativeOperation() toolregistry.Operation {
	fields := make([]toolregistry.InputField, maximumChunkCount)
	for index := range fields {
		fields[index] = toolregistry.InputField{
			Name:         fmt.Sprintf("request_chunk_%02d", index),
			Type:         "string",
			Required:     index == 0,
			MaximumBytes: maximumChunkBytes,
			Enum:         []string{},
		}
	}
	return toolregistry.Operation{
		Name:               NativeOperationName,
		InputSchemaVersion: "coh.tool-input/v1",
		InputFields:        fields,
		BaselineActionTier: "T0",
		MaximumActionTier:  "T0",
		IsolationClass:     "native_restricted",
		CredentialClasses:  []string{"none"},
		ResourceLimits: toolregistry.ResourceLimits{
			WallTimeMilliseconds:  15_000,
			CPUMilliseconds:       15_000,
			MemoryBytes:           512 << 20,
			OutputBytes:           MaximumDocumentBytes,
			EphemeralStorageBytes: 128 << 20,
			ProcessCount:          1,
			OpenFileCount:         32,
		},
		NetworkPolicy: toolregistry.NetworkPolicy{
			Mode:                  "none",
			Protocols:             []string{},
			DNSMode:               "none",
			PublicInternetAllowed: false,
			MetadataAllowed:       false,
			MaximumConnections:    0,
		},
		CancellationMode: "cooperative",
		RetryMode:        "safe",
	}
}
