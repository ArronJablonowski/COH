package deploymentprofile

import "regexp"

var (
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func validate(config Config) string {
	if !uuidV7Pattern.MatchString(config.Change.OrganizationID) || !uuidV7Pattern.MatchString(config.Change.ActorID) || config.Change.Revision == 0 {
		return "change_identity_invalid"
	}
	if (config.Change.Revision == 1 && config.Change.PreviousConfigDigest != "") ||
		(config.Change.Revision > 1 && !digestPattern.MatchString(config.Change.PreviousConfigDigest)) {
		return "change_lineage_invalid"
	}
	if reason := validateConnectivity(config); reason != "" {
		return reason
	}
	if config.Isolation.DockerSocketMounted || config.Isolation.DatabasePublic || config.Isolation.WorkflowPublic || config.Isolation.SecretsInEnvironment {
		return "unsafe_isolation"
	}
	switch config.Deployment.Kind {
	case NativeWorkstation:
		return validateWorkstation(config)
	case NativeServer:
		return validateServer(config)
	case Compose:
		return validateCompose(config)
	default:
		return "unsupported_deployment"
	}
}

func validateWorkstation(config Config) string {
	if config.Deployment.OperatingSys != "darwin" || config.Deployment.Architecture != "arm64" ||
		config.Services.Storage != "sqlite" || config.Services.Workflow != "temporal_development_persistent" ||
		config.Services.Authentication != "local" || config.Services.TransportSecurity != "loopback" ||
		config.Services.EvidenceStore != "local" || config.Isolation.ListenScope != "loopback" {
		return "workstation_profile_mismatch"
	}
	if config.Isolation.DockerRequired || config.Compose.Enabled || !emptyCompose(config.Compose) {
		return "native_docker_dependency"
	}
	if !tokenPattern.MatchString(config.Identities.ControlPlane) || config.Identities.Workflow != "" || config.Identities.Database != "" {
		return "workstation_identity_mismatch"
	}
	return ""
}

func validateServer(config Config) string {
	if config.Deployment.OperatingSys != "linux" || config.Deployment.Architecture != "amd64" ||
		config.Services.Storage != "postgresql_18" || config.Services.Workflow != "temporal_production" ||
		config.Services.Authentication != "oidc" || config.Services.TransportSecurity != "mtls" ||
		config.Services.EvidenceStore != "configured" || config.Isolation.ListenScope != "private" {
		return "server_profile_mismatch"
	}
	if config.Isolation.DockerRequired || config.Compose.Enabled || !emptyCompose(config.Compose) {
		return "native_docker_dependency"
	}
	if !distinctIdentities(config.Identities) {
		return "service_identity_mismatch"
	}
	return ""
}

func validateCompose(config Config) string {
	if !((config.Deployment.OperatingSys == "darwin" || config.Deployment.OperatingSys == "linux" || config.Deployment.OperatingSys == "windows") &&
		(config.Deployment.Architecture == "amd64" || config.Deployment.Architecture == "arm64")) {
		return "compose_platform_mismatch"
	}
	if config.Services.Storage != "postgresql_18" || config.Services.Workflow != "temporal_production" ||
		config.Services.Authentication != "oidc" || config.Services.TransportSecurity != "mtls" || config.Services.EvidenceStore != "configured" ||
		config.Isolation.ListenScope != "private" || !config.Isolation.DockerRequired || !config.Compose.Enabled {
		return "compose_profile_mismatch"
	}
	if !tokenPattern.MatchString(config.Compose.Provider) || !config.Compose.MigrationsRun || !config.Compose.ValidatorsRun || !distinctIdentities(config.Identities) {
		return "compose_component_mismatch"
	}
	for _, component := range []string{"control_plane", "postgresql", "temporal", "migrations", "validator", "provider"} {
		if !digestPattern.MatchString(config.Compose.ImageDigests[component]) {
			return "compose_image_unpinned"
		}
	}
	if len(config.Compose.ImageDigests) != 6 {
		return "compose_image_inventory"
	}
	return ""
}

func validateConnectivity(config Config) string {
	if len(config.Connectivity.EndpointReferences) > 64 || hasDuplicate(config.Connectivity.EndpointReferences) {
		return "endpoint_reference_invalid"
	}
	switch config.Connectivity.Mode {
	case Connected, RestrictedConnected:
		if len(config.Connectivity.EndpointReferences) == 0 || !config.Connectivity.DNSAllowed || !config.Connectivity.InternetAllowed {
			return "connected_route_missing"
		}
		for _, reference := range config.Connectivity.EndpointReferences {
			if !tokenPattern.MatchString(reference) {
				return "endpoint_reference_invalid"
			}
		}
		if !emptyAirGap(config.AirGap) {
			return "connectivity_conflict"
		}
	case AirGapped:
		if len(config.Connectivity.EndpointReferences) != 0 || config.Connectivity.DNSAllowed || config.Connectivity.InternetAllowed ||
			config.Connectivity.TelemetryAllowed || config.Connectivity.UpdatesAllowed || config.Connectivity.ExternalTimeAllowed {
			return "air_gap_egress_enabled"
		}
		if !completeAirGap(config.AirGap) {
			return "air_gap_bundle_incomplete"
		}
	default:
		return "unsupported_connectivity"
	}
	return ""
}

func hasDuplicate(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func distinctIdentities(value Identities) bool {
	return tokenPattern.MatchString(value.ControlPlane) && tokenPattern.MatchString(value.Workflow) && tokenPattern.MatchString(value.Database) &&
		value.ControlPlane != value.Workflow && value.ControlPlane != value.Database && value.Workflow != value.Database
}

func emptyCompose(value ComposeSpec) bool {
	return value.Provider == "" && len(value.ImageDigests) == 0 && !value.MigrationsRun && !value.ValidatorsRun
}

func emptyAirGap(value AirGapSpec) bool {
	return value.BundleManifestDigest == "" && !value.SignedPackages && !value.OCIArchives && !value.Policies && !value.Validators &&
		!value.SBOMs && !value.Provenance && !value.OfflineFeeds && !value.VerificationTools
}

func completeAirGap(value AirGapSpec) bool {
	return digestPattern.MatchString(value.BundleManifestDigest) && value.SignedPackages && value.OCIArchives && value.Policies && value.Validators &&
		value.SBOMs && value.Provenance && value.OfflineFeeds && value.VerificationTools
}
