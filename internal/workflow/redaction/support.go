package redaction

import (
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	timestampLayout      = "2006-01-02T15:04:05.000000000Z"
	maximumArtifactBytes = int64(1 << 30)
	mappingMediaType     = "application/vnd.coh.redaction-mapping+json"
	manifestMediaType    = "application/vnd.coh.artifact-manifest+json"
)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	signaturePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

func validOpaque(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() >= 0 &&
		value.Format(timestampLayout) == formatTime(value)
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validClassification(value string) bool {
	switch value {
	case "public", "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func validCaseState(value string) bool { return value == "open" || value == "closed" }

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && mediaTypePattern.MatchString(value.MediaType) &&
		validClassification(value.Classification) && value.Length > 0 && value.Length <= maximumArtifactBytes
}

func validEvidence(value EvidenceReference) bool {
	return validArtifact(value.Artifact) && validArtifact(value.Manifest) &&
		value.Manifest.MediaType == manifestMediaType &&
		value.Manifest.Classification == value.Artifact.Classification &&
		value.Manifest.Digest != value.Artifact.Digest &&
		allDigests(value.ManifestProvenanceDigest, value.IngestionReceiptDigest)
}

func validHead(value CustodyHead) bool {
	if !validCase(value.Case) || !digestPattern.MatchString(value.ChainHash) ||
		value.Sequence > math.MaxInt64 || (value.Sequence == 0) != (value.LastRecordAt == nil) {
		return false
	}
	if value.Sequence == 0 {
		return value.ChainHash == genesisHash
	}
	return value.ChainHash != genesisHash && validTime(*value.LastRecordAt)
}

func validReplacement(value ReplacementMode) bool {
	return value == Remove || value == Mask || value == Token
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}
