package secretref

import (
	"regexp"
	"strings"
)

var (
	uuidV7Pattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	backendPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	forbiddenBackends = map[string]bool{
		"command": true, "env": true, "environment": true, "inline": true, "url": true,
	}
)

func ValidateReference(reference Reference) error {
	if reference.SchemaVersion != SchemaVersion || reference.ContractVersion != ContractVersion {
		return secretError(InvalidInput, "unsupported_contract", nil)
	}
	if !backendPattern.MatchString(reference.Backend) || !tokenPattern.MatchString(reference.EntryID) || reference.Version == 0 {
		return secretError(InvalidInput, "reference_identity", nil)
	}
	if forbiddenBackends[reference.Backend] {
		return secretError(Denied, "forbidden_backend", nil)
	}
	return nil
}

func ValidateResolutionRequest(request ResolutionRequest) error {
	if request.SchemaVersion != SchemaVersion || request.ContractVersion != ContractVersion {
		return secretError(InvalidInput, "unsupported_contract", nil)
	}
	if !uuidV7Pattern.MatchString(request.RequestID) || !validContext(request.Context) ||
		!validOpaque(request.IdempotencyKey, 1, 128) || !digestPattern.MatchString(request.ActionDigest) ||
		!tokenPattern.MatchString(request.CredentialClass) {
		return secretError(InvalidInput, "resolution_identity", nil)
	}
	if err := ValidateReference(request.Reference); err != nil {
		return err
	}
	return nil
}

func validContext(context Context) bool {
	return uuidV7Pattern.MatchString(context.OrganizationID) && uuidV7Pattern.MatchString(context.TenantID) &&
		uuidV7Pattern.MatchString(context.CaseID) && uuidV7Pattern.MatchString(context.ActorID)
}

func validOpaque(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.ToValidUTF8(value, "") == value && !strings.ContainsAny(value, "\r\n\t")
}
