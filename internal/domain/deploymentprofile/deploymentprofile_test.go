package deploymentprofile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestQualifiedProfileDeclarations(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"workstation-connected", workstation(Connected)},
		{"workstation-air-gap", workstation(AirGapped)},
		{"server-restricted", server()},
		{"compose-connected", compose(Connected)},
		{"compose-air-gap", compose(AirGapped)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluate(context.Background(), encode(t, test.config))
			if err != nil || decision.Outcome != "allowed" || decision.ReasonCode != "profile_valid" {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
			if decision.ConfigDigest == "" || decision.DecisionDigest == "" {
				t.Fatalf("unbound decision = %+v", decision)
			}
		})
	}
}

func TestInsecureAndContradictoryProfilesAreDenied(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		reason string
	}{
		{"native-requires-docker", func(value *Config) { value.Isolation.DockerRequired = true }, "native_docker_dependency"},
		{"docker-socket", func(value *Config) { value.Isolation.DockerSocketMounted = true }, "unsafe_isolation"},
		{"public-database", func(value *Config) { value.Isolation.DatabasePublic = true }, "unsafe_isolation"},
		{"environment-secret", func(value *Config) { value.Isolation.SecretsInEnvironment = true }, "unsafe_isolation"},
		{"hosted-workstation-auth", func(value *Config) { value.Services.Authentication = "oidc" }, "workstation_profile_mismatch"},
		{"server-shared-identity", func(value *Config) { value.Identities.Database = value.Identities.Workflow }, "service_identity_mismatch"},
		{"floating-compose-image", func(value *Config) { value.Compose.ImageDigests["provider"] = "coh-provider:latest" }, "compose_image_unpinned"},
		{"compose-without-migrations", func(value *Config) { value.Compose.MigrationsRun = false }, "compose_component_mismatch"},
		{"air-gap-dns", func(value *Config) { value.Connectivity.DNSAllowed = true }, "air_gap_egress_enabled"},
		{"air-gap-missing-provenance", func(value *Config) { value.AirGap.Provenance = false }, "air_gap_bundle_incomplete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := workstation(AirGapped)
			if strings.HasPrefix(test.name, "server-") {
				config = server()
			}
			if strings.HasPrefix(test.name, "floating-") || strings.HasPrefix(test.name, "compose-") {
				config = compose(Connected)
			}
			test.mutate(&config)
			decision, err := evaluate(context.Background(), encode(t, config))
			if Code(err) != Denied || decision.Outcome != "denied" || decision.ReasonCode != test.reason {
				t.Fatalf("decision = %+v, code = %q, err = %v", decision, Code(err), err)
			}
		})
	}
}

func TestStrictInputAndRedactedErrors(t *testing.T) {
	tests := []string{
		``,
		`{"schema_version":"coh.deployment-profile/v1",`,
		`{"schema_version":"coh.deployment-profile/v1","schema_version":"changed"}`,
		`{"schema_version":"coh.deployment-profile/v1","password":"never-echo-this"}`,
		strings.Repeat("x", MaximumBytes+1),
	}
	for _, input := range tests {
		decision, err := evaluate(context.Background(), []byte(input))
		if Code(err) != InvalidInput || decision.Outcome != "invalid" {
			t.Fatalf("input length %d: decision = %+v, err = %v", len(input), decision, err)
		}
		encoded, marshalErr := json.Marshal(decision)
		if marshalErr != nil || strings.Contains(err.Error()+string(encoded), "never-echo-this") {
			t.Fatalf("unsafe diagnostic = %q %s", err, encoded)
		}
	}
}

func TestCancellationTimeoutAndRecovery(t *testing.T) {
	input := encode(t, workstation(Connected))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := evaluate(canceled, input)
	if Code(err) != Canceled || !errors.Is(err, context.Canceled) || decision.Outcome != "canceled" {
		t.Fatalf("canceled decision = %+v, err = %v", decision, err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	decision, err = evaluate(expired, input)
	if Code(err) != Timeout || !errors.Is(err, context.DeadlineExceeded) || decision.Outcome != "timeout" {
		t.Fatalf("timeout decision = %+v, err = %v", decision, err)
	}
	if decision, err = evaluate(context.Background(), input); err != nil || decision.Outcome != "allowed" {
		t.Fatalf("recovery decision = %+v, err = %v", decision, err)
	}
}

func TestDecisionReplayAndTamperBinding(t *testing.T) {
	config := workstation(Connected)
	first, err := evaluate(context.Background(), encode(t, config))
	if err != nil {
		t.Fatal(err)
	}
	second, err := evaluate(context.Background(), encode(t, config))
	if err != nil || second != first {
		t.Fatalf("replay differs: first=%+v second=%+v err=%v", first, second, err)
	}
	config.Connectivity.EndpointReferences[0] = "provider.secondary"
	changed, err := evaluate(context.Background(), encode(t, config))
	if err != nil || changed.ConfigDigest == first.ConfigDigest || changed.DecisionDigest == first.DecisionDigest {
		t.Fatalf("tamper binding first=%+v changed=%+v err=%v", first, changed, err)
	}
}

func workstation(mode ConnectivityMode) Config {
	config := Config{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		Change:     ChangeControl{OrganizationID: testOrganizationID, ActorID: testActorID, Revision: 1},
		Deployment: Deployment{Kind: NativeWorkstation, OperatingSys: "darwin", Architecture: "arm64"},
		Services:   Services{Storage: "sqlite", Workflow: "temporal_development_persistent", Authentication: "local", TransportSecurity: "loopback", EvidenceStore: "local"},
		Isolation:  Isolation{ListenScope: "loopback"},
		Identities: Identities{ControlPlane: "cohd.local"},
		Compose:    ComposeSpec{ImageDigests: map[string]string{}},
	}
	setConnectivity(&config, mode)
	return config
}

func server() Config {
	config := Config{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		Change:     ChangeControl{OrganizationID: testOrganizationID, ActorID: testActorID, Revision: 1},
		Deployment: Deployment{Kind: NativeServer, OperatingSys: "linux", Architecture: "amd64"},
		Services:   Services{Storage: "postgresql_18", Workflow: "temporal_production", Authentication: "oidc", TransportSecurity: "mtls", EvidenceStore: "configured"},
		Isolation:  Isolation{ListenScope: "private"},
		Identities: Identities{ControlPlane: "cohd.service", Workflow: "temporal.service", Database: "postgresql.service"},
		Compose:    ComposeSpec{ImageDigests: map[string]string{}},
	}
	setConnectivity(&config, RestrictedConnected)
	return config
}

func compose(mode ConnectivityMode) Config {
	config := server()
	config.Deployment = Deployment{Kind: Compose, OperatingSys: "linux", Architecture: "amd64"}
	config.Isolation.DockerRequired = true
	config.Compose = ComposeSpec{Enabled: true, Provider: "local.provider", MigrationsRun: true, ValidatorsRun: true, ImageDigests: map[string]string{
		"control_plane": testDigest, "postgresql": testDigest, "temporal": testDigest,
		"migrations": testDigest, "validator": testDigest, "provider": testDigest,
	}}
	setConnectivity(&config, mode)
	return config
}

func setConnectivity(config *Config, mode ConnectivityMode) {
	config.Connectivity = Connectivity{Mode: mode}
	config.AirGap = AirGapSpec{}
	if mode == AirGapped {
		config.AirGap = AirGapSpec{BundleManifestDigest: testDigest, SignedPackages: true, OCIArchives: true, Policies: true, Validators: true, SBOMs: true, Provenance: true, OfflineFeeds: true, VerificationTools: true}
		return
	}
	config.Connectivity.EndpointReferences = []string{"provider.primary"}
	config.Connectivity.DNSAllowed = true
	config.Connectivity.InternetAllowed = true
}

func encode(t *testing.T, config Config) []byte {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
