package evidencepackage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type packageVerificationError struct{ reason string }

func (value *packageVerificationError) Error() string { return value.reason }
func packageError(reason string) error                { return &packageVerificationError{reason} }

type countingReader struct {
	reader io.Reader
	total  int64
}

func (reader *countingReader) Read(value []byte) (int, error) {
	read, err := reader.reader.Read(value)
	reader.total += int64(read)
	return read, err
}

type verificationReader struct {
	reader io.Reader
	total  int64
}

func (reader *verificationReader) Read(value []byte) (int, error) {
	read, err := reader.reader.Read(value)
	reader.total += int64(read)
	return read, err
}

func readFullContext(ctx context.Context, reader io.Reader, value []byte) error {
	for len(value) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := reader.Read(value)
		value = value[read:]
		if err != nil {
			return err
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func manifestWithinLimits(manifest evidencelifecycle.ExportManifest, header evidencelifecycle.PackageHeader,
	limits evidencelifecycle.PackageLimits) bool {
	if len(manifest.Artifacts) != int(header.ArtifactCount) || manifest.Compression != evidencelifecycle.NoCompression ||
		manifest.Limits.MaximumManifestBytes > limits.MaximumManifestBytes ||
		manifest.Limits.MaximumSignatureBytes > limits.MaximumSignatureBytes ||
		manifest.Limits.MaximumArtifacts > limits.MaximumArtifacts ||
		manifest.Limits.MaximumArtifactBytes > limits.MaximumArtifactBytes ||
		manifest.Limits.MaximumPackageBytes > limits.MaximumPackageBytes {
		return false
	}
	var total int64
	for _, artifact := range manifest.Artifacts {
		if artifact.Reference.Artifact.Length > limits.MaximumArtifactBytes ||
			total > limits.MaximumPackageBytes-artifact.Reference.Artifact.Length {
			return false
		}
		total += artifact.Reference.Artifact.Length
	}
	return total <= limits.MaximumPackageBytes
}

func (worker *Worker) buildVerified(request evidencelifecycle.ImportRequest,
	header evidencelifecycle.PackageHeader, manifest evidencelifecycle.ExportManifest,
	signature evidencelifecycle.DetachedSignature, staged []evidencelifecycle.StagedImportArtifact,
	proof ProofVerification, now time.Time, packageDigest string) (evidencelifecycle.VerifiedImport, error) {
	signatureDigest, err := evidencelifecycle.SignatureBindingDigest(signature)
	if err != nil {
		return evidencelifecycle.VerifiedImport{}, err
	}
	lineageDigest, err := evidencelifecycle.LineageBindingDigest(manifest.Artifacts)
	if err != nil {
		return evidencelifecycle.VerifiedImport{}, err
	}
	componentDigest, err := evidencelifecycle.ComponentSetBindingDigest(manifest.Components)
	if err != nil {
		return evidencelifecycle.VerifiedImport{}, err
	}
	report := evidencelifecycle.ImportVerification{SchemaVersion: evidencelifecycle.ImportVerificationSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion,
		VerificationID:  deterministicPackageUUID("COH-EVIDENCE-IMPORT-VERIFICATION-ID-V1\x00", packageDigest),
		SourceDigest:    request.SourceDigest, PackageDigest: packageDigest, HeaderDigest: header.HeaderDigest,
		ManifestDigest: manifest.ManifestDigest, SignatureDigest: signatureDigest, SigningKeyID: signature.KeyID,
		SigningKeyRevision: signature.KeyRevision, TrustSnapshotDigest: worker.profile.TrustSnapshotDigest,
		RevocationDigest: worker.profile.RevocationDigest, ArtifactSetDigest: manifest.ArtifactSetDigest,
		LineageDigest: lineageDigest, ComponentSetDigest: componentDigest,
		CustodyReportDigest: proof.CustodyReportDigest, AuditCheckpointDigest: proof.AuditCheckpointDigest,
		Outcome: evidencelifecycle.VerificationValid, ReasonCode: evidencelifecycle.VerifySuccess, VerifiedAt: now}
	report.ReportDigest, err = evidencelifecycle.VerificationBindingDigest(report)
	if err != nil || evidencelifecycle.ValidateImportVerification(report) != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import report is invalid")
	}
	packaged := evidencelifecycle.QuarantinedPackage{Reference: request.Reference, Header: header,
		HeaderDigest: header.HeaderDigest, PackageDigest: packageDigest, PackageLength: header.PackageLength,
		ManifestDigest: manifest.ManifestDigest, SignatureDigest: signatureDigest}
	return evidencelifecycle.VerifiedImport{Package: packaged, Manifest: manifest, Signature: signature,
		Verification: report, Staged: staged}, nil
}

func deterministicPackageUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func validDigestText(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func validWorkerLimits(value evidencelifecycle.PackageLimits) bool {
	return value.MaximumManifestBytes > 0 && value.MaximumManifestBytes <= 1<<20 &&
		value.MaximumSignatureBytes >= 64 && value.MaximumSignatureBytes <= 4096 &&
		value.MaximumArtifacts > 0 && value.MaximumArtifacts <= 4096 &&
		value.MaximumArtifactBytes > 0 && value.MaximumArtifactBytes <= 1<<30 &&
		value.MaximumPackageBytes > 0 && value.MaximumPackageBytes <= 4<<40
}

func validWorkerTime(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
