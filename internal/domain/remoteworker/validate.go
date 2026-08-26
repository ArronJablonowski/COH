package remoteworker

import (
	"encoding/base64"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func ValidateScope(scope Scope) error {
	if !validUUID(scope.OrganizationID) || !validUUID(scope.TenantID) {
		return NewError(InvalidInput, "scope_invalid")
	}
	return nil
}

func ValidateTransportIdentity(identity TransportIdentity, now time.Time) error {
	if !validDigest(identity.IdentityDigest) || identity.ObservedAt.IsZero() || now.IsZero() {
		return NewError(InvalidInput, "transport_identity_invalid")
	}
	observed := identity.ObservedAt.UTC()
	if observed.After(now.Add(5*time.Second)) || now.Sub(observed) > MaximumPeerObservationAge {
		return NewError(Denied, "transport_identity_stale")
	}
	switch identity.Kind {
	case "remote_mtls":
		if !identity.MutualTLS || !validDigest(identity.CertificateFingerprint) || identity.CertificateRevision == 0 ||
			identity.CertificateNotBefore.IsZero() || identity.CertificateNotAfter.IsZero() ||
			now.Before(identity.CertificateNotBefore.UTC()) || !now.Before(identity.CertificateNotAfter.UTC()) ||
			!validWorkerURI(identity.URISAN) || identity.SocketPath != "" || identity.PeerAuthenticated || identity.PlatformPeerAuth {
			return NewError(Denied, "mutual_tls_identity_invalid")
		}
	case "local_socket_authenticated":
		if identity.MutualTLS || identity.CertificateFingerprint != "" || identity.CertificateRevision != 0 || identity.URISAN != "" ||
			!filepath.IsAbs(identity.SocketPath) || strings.ContainsRune(identity.SocketPath, '\x00') ||
			identity.SocketMode&0007 != 0 || identity.SocketMode&^0777 != 0 || identity.SocketMode == 0 ||
			!identity.PeerAuthenticated || !identity.PlatformPeerAuth || identity.PeerPID == 0 ||
			identity.PeerUID != identity.SocketOwnerUID || identity.PeerGID != identity.SocketOwnerGID {
			return NewError(Denied, "local_peer_identity_invalid")
		}
	default:
		return NewError(Denied, "transport_kind_unsupported")
	}
	return nil
}

func ValidateAttestation(attestation CapabilityAttestation) error {
	if attestation.SchemaVersion != AttestationSchemaVersion || attestation.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_attestation_contract")
	}
	if err := ValidateScope(attestation.Scope); err != nil {
		return err
	}
	if !validToken(attestation.WorkerID) || !validNonce(attestation.EnrollmentNonce) ||
		!validDigest(attestation.TransportIdentityDigest) || !validDigest(attestation.CertificateFingerprint) ||
		attestation.CertificateRevision == 0 ||
		!validPlatform(attestation.PlatformOS, attestation.PlatformArchitecture) ||
		!validDigest(attestation.ExecutorDigest) || !validDigest(attestation.RuntimeDigest) ||
		!validDigest(attestation.ToolRegistryDigest) {
		return NewError(InvalidInput, "attestation_identity_invalid")
	}
	if !validSortedSet(attestation.IsolationClasses, 1, 3, validIsolation) {
		return NewError(Denied, "isolation_capability_invalid")
	}
	if attestation.MaximumActionTier != "T0" && attestation.MaximumActionTier != "T1" &&
		attestation.MaximumActionTier != "T2" && attestation.MaximumActionTier != "T3" {
		return NewError(Denied, "tier_capability_invalid")
	}
	if !validResources(attestation.Resources) || !validSortedSet(attestation.NetworkModes, 1, 2, validNetworkMode) {
		return NewError(Denied, "execution_capability_invalid")
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, attestation.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, attestation.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issued.Location() != time.UTC || expires.Location() != time.UTC ||
		!issued.Before(expires) || expires.Sub(issued) > MaximumAttestationAge {
		return NewError(InvalidInput, "attestation_lifetime_invalid")
	}
	return nil
}

func ValidateEnrollmentRequest(request EnrollmentRequest) error {
	if request.SchemaVersion != EnrollmentSchemaVersion || request.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_enrollment_contract")
	}
	if !validUUID(request.RequestID) || !validOpaque(request.IdempotencyKey, 1, 128) ||
		!validToken(request.WorkerID) || !validNonce(request.EnrollmentNonce) || len(request.SignedAttestation) == 0 ||
		len(request.SignedAttestation) > MaximumInputBytes {
		return NewError(InvalidInput, "enrollment_identity_invalid")
	}
	return ValidateScope(request.Scope)
}

func ValidateEnrollmentAuthority(authority EnrollmentAuthority, now time.Time) error {
	if err := ValidateScope(authority.Scope); err != nil {
		return err
	}
	if !validToken(authority.WorkerID) || !validDigest(authority.EnrollmentDecisionDigest) ||
		!validNonce(authority.ExpectedEnrollmentNonce) || !validToken(authority.AttestationKeyID) ||
		authority.AttestationKeyRevision == 0 || len(authority.AttestationPublicKey) != 32 {
		return NewError(InvalidInput, "enrollment_authority_invalid")
	}
	if !authority.EnrollmentAllowed {
		return NewError(Denied, "enrollment_denied")
	}
	if authority.Transport.Kind != "remote_mtls" {
		return NewError(Denied, "remote_mtls_required")
	}
	if err := ValidateTransportIdentity(authority.Transport, now); err != nil {
		return err
	}
	if authority.Transport.URISAN != ExpectedWorkerURISAN(authority.Scope, authority.WorkerID) {
		return NewError(Denied, "worker_uri_san_mismatch")
	}
	return nil
}

func ValidateLeaseRequest(request LeaseRequest) error {
	if request.SchemaVersion != LeaseSchemaVersion || request.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_lease_contract")
	}
	if !validUUID(request.RequestID) || !validOpaque(request.IdempotencyKey, 1, 128) ||
		!validToken(request.WorkerID) || request.RequestedTTLSeconds == 0 ||
		request.RequestedTTLSeconds > MaximumLeaseTTLSeconds {
		return NewError(InvalidInput, "lease_identity_invalid")
	}
	return ValidateLeaseScope(request.Scope)
}

func ValidateLeaseScope(scope LeaseScope) error {
	if !validUUID(scope.OrganizationID) || !validUUID(scope.TenantID) || !validUUID(scope.CaseID) ||
		!validUUID(scope.ActorID) || !validUUID(scope.TaskID) || !validDigest(scope.ActionDigest) ||
		!validTargetDigests(scope.TargetDigests) || !validToken(scope.ToolName) || !validToken(scope.ToolVersion) ||
		!validDigest(scope.ToolDigest) || !validDigest(scope.ToolRegistryDigest) || !validToken(scope.Operation) ||
		!validIsolation(scope.IsolationClass) ||
		!validResources(scope.Resources) || !validNetworkMode(scope.NetworkMode) ||
		!validDigest(scope.ResourcePolicyDigest) || !validDigest(scope.NetworkPolicyDigest) {
		return NewError(InvalidInput, "lease_scope_invalid")
	}
	if scope.RequiredTier != "T0" && scope.RequiredTier != "T1" && scope.RequiredTier != "T2" && scope.RequiredTier != "T3" {
		return NewError(Denied, "lease_tier_invalid")
	}
	return nil
}

func ValidateLeaseAuthority(authority LeaseAuthority, now time.Time) error {
	if err := ValidateLeaseScope(authority.Scope); err != nil {
		return err
	}
	if authority.ActorRevision == 0 || !validDigest(authority.AuthorizationDecisionDigest) ||
		!validDigest(authority.PolicyDecisionDigest) || authority.ObservedAt.IsZero() {
		return NewError(InvalidInput, "lease_authority_invalid")
	}
	if authority.ApprovalRequired && !validDigest(authority.ApprovalDecisionDigest) {
		return NewError(InvalidInput, "lease_authority_invalid")
	}
	if !authority.ApprovalRequired && (authority.ApprovalAllowed || authority.ApprovalDecisionDigest != "") {
		return NewError(InvalidInput, "lease_authority_invalid")
	}
	if !authority.ActorActive || !authority.TaskActive || authority.EmergencyStopActive ||
		!authority.AuthorizationAllowed || !authority.PolicyAllowed ||
		(authority.ApprovalRequired && !authority.ApprovalAllowed) {
		return NewError(Denied, "lease_authority_denied")
	}
	observed := authority.ObservedAt.UTC()
	if observed.After(now.Add(5*time.Second)) || now.Sub(observed) > MaximumPeerObservationAge {
		return NewError(Denied, "lease_authority_stale")
	}
	if err := ValidateWorkerRecord(authority.Worker, now); err != nil {
		return err
	}
	if authority.Transport.Kind != "remote_mtls" {
		return NewError(Denied, "remote_mtls_required")
	}
	if err := ValidateTransportIdentity(authority.Transport, now); err != nil {
		return err
	}
	if authority.Transport.IdentityDigest != authority.Worker.TransportIdentityDigest ||
		authority.Transport.CertificateFingerprint != authority.Worker.CertificateFingerprint ||
		authority.Transport.CertificateRevision != authority.Worker.CertificateRevision {
		return NewError(Denied, "worker_transport_mismatch")
	}
	if authority.Transport.URISAN != ExpectedWorkerURISAN(authority.Worker.Scope, authority.Worker.WorkerID) {
		return NewError(Denied, "worker_uri_san_mismatch")
	}
	return nil
}

func ValidateWorkerRecord(worker WorkerRecord, now time.Time) error {
	if err := ValidateScope(worker.Scope); err != nil {
		return err
	}
	if !validToken(worker.WorkerID) || worker.Revision == 0 || !worker.Active ||
		!validDigest(worker.TransportIdentityDigest) || !validDigest(worker.CertificateFingerprint) ||
		worker.CertificateRevision == 0 || !validDigest(worker.AttestationDigest) ||
		!validToken(worker.AttestationKeyID) || worker.AttestationKeyRevision == 0 ||
		!validDigest(worker.AttestationKeyDigest) || worker.EnrolledAt.IsZero() {
		return NewError(Denied, "worker_record_invalid")
	}
	if err := ValidateAttestation(worker.Attestation); err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339Nano, worker.Attestation.ExpiresAt)
	if !now.Before(expires) {
		return NewError(Denied, "worker_attestation_expired")
	}
	if worker.Attestation.Scope != worker.Scope || worker.Attestation.WorkerID != worker.WorkerID ||
		worker.Attestation.TransportIdentityDigest != worker.TransportIdentityDigest ||
		worker.Attestation.CertificateFingerprint != worker.CertificateFingerprint ||
		worker.Attestation.CertificateRevision != worker.CertificateRevision {
		return NewError(Denied, "worker_record_binding_invalid")
	}
	return nil
}

func ValidateDispatchRequest(request DispatchRequest) error {
	if request.SchemaVersion != DispatchSchemaVersion || request.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_dispatch_contract")
	}
	if !validUUID(request.LeaseID) || !validToken(request.WorkerID) {
		return NewError(InvalidInput, "dispatch_identity_invalid")
	}
	return ValidateLeaseScope(request.Scope)
}

func ValidateRevocationRequest(request RevocationRequest) error {
	if request.SchemaVersion != RevocationSchemaVersion || request.ContractVersion != ContractVersion {
		return NewError(Denied, "unsupported_revocation_contract")
	}
	if !validUUID(request.RequestID) {
		return NewError(InvalidInput, "revocation_identity_invalid")
	}
	if err := ValidateScope(request.Scope); err != nil {
		return err
	}
	switch request.Kind {
	case "worker", "certificate", "attestation":
		if !validToken(request.WorkerID) || request.LeaseID != "" {
			return NewError(InvalidInput, "revocation_identity_invalid")
		}
	case "lease":
		if !validUUID(request.LeaseID) || request.WorkerID != "" {
			return NewError(InvalidInput, "revocation_identity_invalid")
		}
	default:
		return NewError(InvalidInput, "revocation_kind_invalid")
	}
	switch request.Reason {
	case "operator_revoked", "certificate_revoked", "attestation_revoked", "worker_revoked", "task_canceled", "emergency_stop", "audit_unavailable":
		return nil
	default:
		return NewError(InvalidInput, "revocation_reason_invalid")
	}
}

func validResources(value ResourceCapacity) bool {
	return value.WallTimeMilliseconds > 0 && value.CPUMilliseconds > 0 && value.MemoryBytes >= 1<<20 &&
		value.OutputBytes > 0 && value.EphemeralStorageBytes > 0 && value.ProcessCount > 0 && value.OpenFileCount > 0
}

func validIsolation(value string) bool {
	switch value {
	case "native_restricted", "oci_sandbox", "remote_isolated":
		return true
	default:
		return false
	}
}

func validNetworkMode(value string) bool { return value == "none" || value == "brokered_egress" }

func validSortedSet(values []string, minimum, maximum int, valid func(string) bool) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validTargetDigests(values []string) bool { return validSortedSet(values, 1, 64, validDigest) }

func validWorkerURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" && parsed.Path != "" &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
}

func ExpectedWorkerURISAN(scope Scope, workerID string) string {
	return "spiffe://coh.internal/organization/" + scope.OrganizationID + "/tenant/" + scope.TenantID + "/worker/" + workerID
}

func validPlatform(osName, architecture string) bool {
	return (osName == "linux" || osName == "darwin" || osName == "windows") &&
		(architecture == "amd64" || architecture == "arm64")
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 16 && len(decoded) <= 64
}

func validUUID(value string) bool {
	if len(value) != 36 || value[14] != '7' || !strings.Contains("89ab", value[19:20]) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value &&
		!strings.ContainsAny(value, "\r\n\t")
}
