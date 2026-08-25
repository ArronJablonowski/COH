package credentiallease

import (
	"errors"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

func ValidateIssuanceRequest(request IssuanceRequest) error {
	if request.SchemaVersion != SchemaVersion || request.ContractVersion != ContractVersion {
		return leaseError(InvalidInput, "unsupported_contract", nil)
	}
	if !validUUID(request.RequestID) || !validOpaque(request.IdempotencyKey, 1, 128) ||
		!validContext(request.Context) || !validUUID(request.TaskID) || !validDigest(request.ActionDigest) ||
		!validToken(request.Operation) || !validToken(request.CredentialClass) {
		return leaseError(InvalidInput, "issuance_identity", nil)
	}
	if !validTargets(request.TargetDigests) {
		return leaseError(InvalidInput, "target_scope", nil)
	}
	if (request.Audience.Kind != "connector" && request.Audience.Kind != "runner") ||
		!validToken(request.Audience.ID) || !validDigest(request.Audience.TransportIdentityDigest) {
		return leaseError(InvalidInput, "audience_scope", nil)
	}
	if request.RequestedTTLSeconds == 0 || request.RequestedTTLSeconds > MaximumTTLSeconds {
		return leaseError(InvalidInput, "lease_lifetime", nil)
	}
	if err := secretref.ValidateReference(request.Reference); err != nil {
		return mapSecretError(err)
	}
	return nil
}

func validTargets(targets []string) bool {
	if len(targets) == 0 || len(targets) > 64 || !slices.IsSorted(targets) {
		return false
	}
	for index, target := range targets {
		if !validDigest(target) || (index > 0 && target == targets[index-1]) {
			return false
		}
	}
	return true
}

func validContext(context secretref.Context) bool {
	return validUUID(context.OrganizationID) && validUUID(context.TenantID) &&
		validUUID(context.CaseID) && validUUID(context.ActorID)
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

func mapSecretError(err error) error {
	reason := "reference_invalid"
	var secretErr *secretref.Error
	if errors.As(err, &secretErr) {
		reason = secretErr.Reason
	}
	code := InvalidInput
	if secretref.Code(err) == secretref.Denied {
		code = Denied
	}
	return leaseError(code, reason, nil)
}
