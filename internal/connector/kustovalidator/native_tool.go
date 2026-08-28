package kustovalidator

import "github.com/ArronJablonowski/COH/internal/domain/toolregistry"

const (
	NativeToolName      = "kusto.validator"
	NativeToolVersion   = "1.0.0"
	NativeOperationName = "validate"
)

// NativeOperation is the immutable credentialless execution surface embedded
// in the reviewed and publisher-signed manifest for the helper artifact.
func NativeOperation() toolregistry.Operation {
	fields := make([]toolregistry.InputField, 8)
	for index := range fields {
		fields[index] = toolregistry.InputField{
			Name:         "request_chunk_0" + string(rune('0'+index)),
			Type:         "string",
			Required:     index == 0,
			MaximumBytes: 61_440,
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
			WallTimeMilliseconds:  5_000,
			CPUMilliseconds:       5_000,
			MemoryBytes:           512 << 20,
			OutputBytes:           2 << 20,
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
