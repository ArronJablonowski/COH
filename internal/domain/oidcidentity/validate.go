package oidcidentity

import (
	"encoding/base64"
	"net/url"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

var algorithmOrder = map[string]int{"EdDSA": 1, "ES256": 2, "RS256": 3}

func ValidateProviderConfig(config ProviderConfig) error {
	if config.SchemaVersion != SchemaVersion || config.ContractVersion != ContractVersion {
		return oidcError(localidentity.InvalidInput, "unsupported_contract", nil)
	}
	if config.ProfileKind != "native_server" && config.ProfileKind != "compose" {
		return oidcError(localidentity.InvalidInput, "provider_profile", nil)
	}
	if !validIssuer(config.Issuer) {
		return oidcError(localidentity.InvalidInput, "provider_issuer", nil)
	}
	if !validSortedOpaque(config.Audiences, 1, 8, 256) {
		return oidcError(localidentity.InvalidInput, "provider_audience", nil)
	}
	if !validAlgorithms(config.AllowedAlgorithms) {
		return oidcError(localidentity.InvalidInput, "provider_algorithm", nil)
	}
	if !validToken(config.JWKSReference) {
		return oidcError(localidentity.InvalidInput, "provider_jwks", nil)
	}
	if config.TransportSecurity != "mtls" {
		return oidcError(localidentity.InvalidInput, "provider_transport", nil)
	}
	if !validDigest(config.ProfileDecisionDigest) {
		return oidcError(localidentity.InvalidInput, "provider_profile_digest", nil)
	}
	if config.MaximumTokenAgeSeconds < 60 || config.MaximumTokenAgeSeconds > 900 || config.ClockSkewSeconds > 60 {
		return oidcError(localidentity.InvalidInput, "provider_time", nil)
	}
	return nil
}

func ValidateClaims(claims Claims) error {
	if !validIssuer(claims.Issuer) {
		return oidcError(localidentity.InvalidInput, "claims_issuer", nil)
	}
	if !validOpaque(claims.Subject, 1, 256) || !validOpaque(claims.JWTID, 1, 128) ||
		!validUUID(claims.OrganizationID) || !validUUID(claims.ActorID) {
		return oidcError(localidentity.InvalidInput, "claims_identity", nil)
	}
	if !validSortedOpaque(claims.Audiences, 1, 8, 256) {
		return oidcError(localidentity.InvalidInput, "claims_audience", nil)
	}
	if claims.ExpiresAt <= claims.IssuedAt || claims.NotBefore > claims.IssuedAt || claims.NotBefore <= 0 {
		return oidcError(localidentity.InvalidInput, "claims_time", nil)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(claims.Nonce)
	if err != nil || len(nonce) != 32 {
		return oidcError(localidentity.InvalidInput, "claims_nonce", nil)
	}
	if !validRoles(claims.Roles) {
		return oidcError(localidentity.InvalidInput, "claims_roles", nil)
	}
	if !validSortedUUIDs(claims.TenantIDs, 64) {
		return oidcError(localidentity.InvalidInput, "claims_tenants", nil)
	}
	return nil
}

func validIssuer(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validAlgorithms(values []string) bool {
	if len(values) == 0 || len(values) > len(algorithmOrder) {
		return false
	}
	previous := 0
	for _, value := range values {
		rank := algorithmOrder[value]
		if rank == 0 || rank <= previous {
			return false
		}
		previous = rank
	}
	return true
}

func validRoles(roles []localidentity.Role) bool {
	if len(roles) == 0 || len(roles) > 5 || !slices.IsSorted(roles) {
		return false
	}
	for index, role := range roles {
		switch role {
		case localidentity.Administrator, localidentity.Analyst, localidentity.Approver, localidentity.Auditor, localidentity.Service:
		default:
			return false
		}
		if index > 0 && role == roles[index-1] {
			return false
		}
	}
	return len(roles) == 1 || !slices.Contains(roles, localidentity.Service)
}

func validSortedUUIDs(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validUUID(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validSortedOpaque(values []string, minimum, maximum, maxLength int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validOpaque(value, 1, maxLength) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
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
