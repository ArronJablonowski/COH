package command

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/deploymentprofile"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
	"github.com/ArronJablonowski/COH/internal/transport/oidcauth"
)

// ErrServerOIDCComposition is deliberately opaque: configuration values and
// backend details are not safe startup diagnostics.
var ErrServerOIDCComposition = errors.New("server OIDC composition denied")

// ServerOIDCDependencies are the explicit runtime capabilities needed by the
// native-server and Compose authentication boundary.
type ServerOIDCDependencies struct {
	ProfileAudit deploymentprofile.AuditSink
	Actors       oidcauth.ActorDirectory
	States       oidcauth.StateStore
	Sessions     oidcauth.SessionStore
	Replay       oidcauth.ReplayStore
	Keys         oidcauth.KeySource
	Audit        oidcauth.AuditSink
	Random       io.Reader
	Clock        oidcauth.Clock
	StateTTL     time.Duration
	SessionTTL   time.Duration
}

// ComposeServerOIDC validates and audits the deployment declaration before it
// binds OIDC to that exact allowed decision. No local-auth fallback exists.
func ComposeServerOIDC(
	ctx context.Context,
	profileInput []byte,
	authority deploymentprofile.AuthoritySnapshot,
	provider oidcidentity.ProviderConfig,
	dependencies ServerOIDCDependencies,
) (oidcauth.Service, deploymentprofile.Decision, error) {
	decision, err := (deploymentprofile.Validator{Audit: dependencies.ProfileAudit}).Validate(ctx, profileInput, authority)
	if err != nil {
		return oidcauth.Service{}, decision, err
	}
	var profile deploymentprofile.Config
	if err := json.Unmarshal(profileInput, &profile); err != nil {
		return oidcauth.Service{}, decision, ErrServerOIDCComposition
	}
	if decision.Outcome != "allowed" || decision.ReasonCode != "profile_valid" ||
		(profile.Deployment.Kind != deploymentprofile.NativeServer && profile.Deployment.Kind != deploymentprofile.Compose) ||
		profile.Services.Authentication != "oidc" || profile.Services.TransportSecurity != "mtls" ||
		provider.ProfileKind != string(profile.Deployment.Kind) || provider.ProfileDecisionDigest != decision.DecisionDigest ||
		oidcidentity.ValidateProviderConfig(provider) != nil || dependencies.Actors == nil || dependencies.States == nil ||
		dependencies.Sessions == nil || dependencies.Replay == nil || dependencies.Keys == nil || dependencies.Audit == nil {
		return oidcauth.Service{}, decision, ErrServerOIDCComposition
	}
	service := oidcauth.Service{
		Config: provider, Actors: dependencies.Actors, States: dependencies.States,
		Sessions: dependencies.Sessions, Replay: dependencies.Replay, Keys: dependencies.Keys,
		Audit: dependencies.Audit, Random: dependencies.Random, Clock: dependencies.Clock,
		StateTTL: dependencies.StateTTL, SessionTTL: dependencies.SessionTTL,
	}
	return service, decision, nil
}
