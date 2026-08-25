package postgres

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

func TestOpenRejectsUnsafeConfigurationBeforeConnecting(t *testing.T) {
	verifier := testBackupVerifier{}
	tests := []struct {
		name   string
		config Config
		code   workflow.StorageErrorCode
	}{
		{name: "missing", config: Config{}, code: workflow.StorageInvalidInput},
		{name: "connection-bound", config: Config{URL: "postgres://user@example.invalid/db", MaxConnections: 129, BootstrapBackupDigest: testBootstrapDigest, BackupVerifier: verifier}, code: workflow.StorageInvalidInput},
		{name: "plaintext-remote", config: Config{URL: "postgres://user@example.invalid/db?sslmode=disable", MaxConnections: 1, BootstrapBackupDigest: testBootstrapDigest, BackupVerifier: verifier}, code: workflow.StorageDenied},
		{name: "plaintext-loopback-not-enabled", config: Config{URL: "postgres://user@127.0.0.1:1/db?sslmode=disable", MaxConnections: 1, BootstrapBackupDigest: testBootstrapDigest, BackupVerifier: verifier}, code: workflow.StorageDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Open(context.Background(), test.config)
			if workflow.StorageCode(err) != test.code {
				t.Fatalf("code = %q, err = %v", workflow.StorageCode(err), err)
			}
		})
	}
}
