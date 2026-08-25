package command

import (
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/deploymentprofile"
	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
	"github.com/ArronJablonowski/COH/internal/transport/oidcauth"
)

type compositionAudit struct {
	profileErr error
	decisions  []deploymentprofile.Decision
	events     []oidcauth.Event
}

func (audit *compositionAudit) AppendProfileDecision(_ context.Context, decision deploymentprofile.Decision) error {
	audit.decisions = append(audit.decisions, decision)
	return audit.profileErr
}

func (audit *compositionAudit) AppendOIDCEvent(_ context.Context, event oidcauth.Event) error {
	audit.events = append(audit.events, event)
	return nil
}

func (audit *compositionAudit) AppendAuthorizationDecision(context.Context, localidentity.Decision) error {
	return nil
}

type compositionRuntime struct{}

func (compositionRuntime) LookupOIDCActor(context.Context, string, string) (localidentity.Actor, error) {
	return localidentity.Actor{}, oidcauth.ErrNotFound
}
func (compositionRuntime) LookupActor(context.Context, string, string) (localidentity.Actor, error) {
	return localidentity.Actor{}, oidcauth.ErrNotFound
}
func (compositionRuntime) SaveLoginState(context.Context, oidcauth.LoginStateRecord) error {
	return nil
}
func (compositionRuntime) TakeLoginState(context.Context, string) (oidcauth.LoginStateRecord, error) {
	return oidcauth.LoginStateRecord{}, oidcauth.ErrNotFound
}
func (compositionRuntime) SaveSession(context.Context, oidcauth.SessionRecord) error { return nil }
func (compositionRuntime) LookupSession(context.Context, string) (oidcauth.SessionRecord, error) {
	return oidcauth.SessionRecord{}, oidcauth.ErrNotFound
}
func (compositionRuntime) RevokeSession(context.Context, string, time.Time) error { return nil }
func (compositionRuntime) CheckAndStore(context.Context, oidcauth.ReplayRecord) (oidcauth.ReplayResult, error) {
	return oidcauth.ReplayNew, nil
}
func (compositionRuntime) LookupKey(context.Context, string, string, string) (oidcauth.KeyRecord, error) {
	return oidcauth.KeyRecord{PublicKey: crypto.PublicKey(nil)}, oidcauth.ErrNotFound
}

func TestComposeServerOIDCBindsAuditedProfiles(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture string
		kind    string
	}{
		{"native-server", "native-server-restricted.json", "native_server"},
		{"compose-connected", "compose-connected.json", "compose"},
		{"compose-air-gap", "compose-air-gap.json", "compose"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := profileFixture(t, test.fixture)
			audit := &compositionAudit{}
			authority := compositionAuthority()
			provider := compositionProvider(test.kind, strings.Repeat("a", 64))
			// Obtain the deterministic decision digest used by the provider's
			// immutable startup declaration, then compose through a fresh audit.
			preflight, err := (deploymentprofile.Validator{Audit: audit}).Validate(context.Background(), input, authority)
			if err != nil {
				t.Fatal(err)
			}
			provider.ProfileDecisionDigest = preflight.DecisionDigest
			service, decision, err := ComposeServerOIDC(context.Background(), input, authority, provider, compositionDependencies(audit))
			if err != nil || decision.Outcome != "allowed" || service.Config.ProfileKind != test.kind || len(audit.decisions) != 2 {
				t.Fatalf("decision = %+v, config = %+v, audits = %d, err = %v", decision, service.Config, len(audit.decisions), err)
			}
			state, err := service.Begin(context.Background(), oidcauth.BeginRequest{OrganizationID: authority.OrganizationID, Audience: "coh-server"})
			if err != nil || state.ID == "" || len(audit.events) != 1 {
				t.Fatalf("state = %+v, events = %d, err = %v", state, len(audit.events), err)
			}
		})
	}
}

func TestComposeServerOIDCRejectsUnboundOrUnsupportedProfiles(t *testing.T) {
	authority := compositionAuthority()
	for _, test := range []struct {
		name    string
		fixture string
		kind    string
		digest  string
	}{
		{"workstation", "native-workstation-connected.json", "native_server", ""},
		{"wrong-kind", "native-server-restricted.json", "compose", "decision"},
		{"wrong-decision", "native-server-restricted.json", "native_server", "sha256:" + strings.Repeat("f", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := profileFixture(t, test.fixture)
			audit := &compositionAudit{}
			provider := compositionProvider(test.kind, strings.Repeat("a", 64))
			if test.digest == "decision" {
				decision, err := (deploymentprofile.Validator{Audit: audit}).Validate(context.Background(), input, authority)
				if err != nil {
					t.Fatal(err)
				}
				provider.ProfileDecisionDigest = decision.DecisionDigest
			} else if test.digest != "" {
				provider.ProfileDecisionDigest = test.digest
			}
			service, _, err := ComposeServerOIDC(context.Background(), input, authority, provider, compositionDependencies(audit))
			if !errors.Is(err, ErrServerOIDCComposition) || service.Config.Issuer != "" {
				t.Fatalf("service = %+v, err = %v", service, err)
			}
		})
	}
}

func TestComposeServerOIDCRequiresProfileAuditAndRuntimePorts(t *testing.T) {
	input := profileFixture(t, "native-server-restricted.json")
	authority := compositionAuthority()
	preflightAudit := &compositionAudit{}
	decision, err := (deploymentprofile.Validator{Audit: preflightAudit}).Validate(context.Background(), input, authority)
	if err != nil {
		t.Fatal(err)
	}
	provider := compositionProvider("native_server", strings.Repeat("a", 64))
	provider.ProfileDecisionDigest = decision.DecisionDigest

	auditFailure := &compositionAudit{profileErr: errors.New("database password must not escape")}
	_, failedDecision, err := ComposeServerOIDC(context.Background(), input, authority, provider, compositionDependencies(auditFailure))
	if deploymentprofile.Code(err) != deploymentprofile.Unavailable || failedDecision.Outcome != "unavailable" || strings.Contains(err.Error(), "password") {
		t.Fatalf("decision = %+v, err = %v", failedDecision, err)
	}

	dependencies := compositionDependencies(&compositionAudit{})
	dependencies.Keys = nil
	service, _, err := ComposeServerOIDC(context.Background(), input, authority, provider, dependencies)
	if !errors.Is(err, ErrServerOIDCComposition) || service.Config.Issuer != "" {
		t.Fatalf("service = %+v, err = %v", service, err)
	}
}

func compositionDependencies(audit *compositionAudit) ServerOIDCDependencies {
	runtime := compositionRuntime{}
	return ServerOIDCDependencies{ProfileAudit: audit, Actors: runtime, States: runtime, Sessions: runtime,
		Replay: runtime, Keys: runtime, Audit: audit, Random: strings.NewReader(strings.Repeat("r", 512))}
}

func compositionProvider(kind, fill string) oidcidentity.ProviderConfig {
	return oidcidentity.ProviderConfig{SchemaVersion: oidcidentity.SchemaVersion, ContractVersion: oidcidentity.ContractVersion,
		ProfileKind: kind, Issuer: "https://identity.example.invalid/tenant-a", Audiences: []string{"coh-server"},
		AllowedAlgorithms: []string{"EdDSA", "ES256", "RS256"}, JWKSReference: "identity.primary", TransportSecurity: "mtls",
		ProfileDecisionDigest: "sha256:" + fill, MaximumTokenAgeSeconds: 300, ClockSkewSeconds: 30}
}

func compositionAuthority() deploymentprofile.AuthoritySnapshot {
	return deploymentprofile.AuthoritySnapshot{OrganizationID: "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e",
		ActorID: "0198d6c4-1111-7111-8111-111111111111", Active: true}
}

func profileFixture(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "contracts", "deployment", "v1", "fixtures", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	return input
}
