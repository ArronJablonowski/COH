package evidencelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const genesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)
	tokenPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	signaturePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && mediaTypePattern.MatchString(value.MediaType) &&
		validClassification(value.Classification) && value.Length > 0 && value.Length <= 1<<30
}

func validEvidence(value EvidenceReference) bool {
	return validArtifact(value.Artifact) && validArtifact(value.Manifest) &&
		value.Manifest.MediaType == "application/vnd.coh.artifact-manifest+json" &&
		value.Manifest.Classification == value.Artifact.Classification && value.Manifest.Digest != value.Artifact.Digest &&
		allDigests(value.ManifestProvenanceDigest, value.IngestionReceiptDigest)
}

func validHead(value CustodyHead) bool {
	if !validCase(value.Case) || !digestPattern.MatchString(value.ChainHash) || value.Sequence > math.MaxInt64 {
		return false
	}
	if value.Sequence == 0 {
		return value.ChainHash == genesisHash && value.LastRecordAt == nil
	}
	return value.ChainHash != genesisHash && value.LastRecordAt != nil && validTime(*value.LastRecordAt)
}

func sameHead(left, right CustodyHead) bool {
	if left.Case != right.Case || left.Sequence != right.Sequence || left.ChainHash != right.ChainHash ||
		(left.LastRecordAt == nil) != (right.LastRecordAt == nil) {
		return false
	}
	return left.LastRecordAt == nil || left.LastRecordAt.Equal(*right.LastRecordAt)
}

func validLimits(value PackageLimits) bool {
	return value.MaximumManifestBytes > 0 && value.MaximumManifestBytes <= 16<<20 &&
		value.MaximumSignatureBytes >= 64 && value.MaximumSignatureBytes <= 4096 &&
		value.MaximumArtifacts > 0 && value.MaximumArtifacts <= 4096 &&
		value.MaximumArtifactBytes > 0 && value.MaximumArtifactBytes <= 1<<30 &&
		value.MaximumPackageBytes > 0 && value.MaximumPackageBytes <= 4<<40 &&
		value.MaximumArtifactBytes <= value.MaximumPackageBytes
}

func validOperation(value Operation) bool {
	return value == Export || value == Import || value == PlaceHold || value == ReleaseHold || value == Delete
}

func validPhase(value Phase) bool {
	for _, candidate := range []Phase{Planned, Quarantined, Verified, Authorized, Packaged, Published,
		CaseRecorded, Tombstoned, Disposed, Custodied, Completed} {
		if value == candidate {
			return true
		}
	}
	return false
}

func validClassification(value string) bool {
	return value == "public" || value == "internal" || value == "confidential" || value == "restricted"
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() >= 0
}

func validOpaque(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validRevision(value uint64) bool { return value > 0 && value <= math.MaxInt64 }

func allDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func allPointerDigests(values ...*string) bool {
	for _, value := range values {
		if value != nil && !digestPattern.MatchString(*value) {
			return false
		}
	}
	return true
}

func allNil(values ...*string) bool {
	for _, value := range values {
		if value != nil {
			return false
		}
	}
	return true
}

func digest(prefix string, input []byte) string {
	sum := sha256.Sum256(append([]byte(prefix), input...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
