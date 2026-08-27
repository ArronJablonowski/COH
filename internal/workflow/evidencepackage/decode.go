package evidencepackage

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func (worker *Worker) VerifyImport(ctx context.Context,
	request evidencelifecycle.ImportRequest) (evidencelifecycle.VerifiedImport, error) {
	if ctx == nil || request.Reference == "" || !validDigestText(request.SourceDigest) ||
		!validDigestText(request.PackageDigest) || !validWorkerLimits(request.Limits) || !validWorkerTime(request.Deadline) {
		return evidencelifecycle.VerifiedImport{}, packageError("import request is invalid")
	}
	reader, err := worker.inputs.OpenInput(ctx, request.Reference)
	if err != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import input is unavailable")
	}
	defer reader.Close()
	return worker.verifyStream(ctx, bufio.NewReaderSize(reader, 64<<10), request)
}

func (worker *Worker) verifyStream(ctx context.Context, source *bufio.Reader,
	request evidencelifecycle.ImportRequest) (evidencelifecycle.VerifiedImport, error) {
	hasher := sha256.New()
	counted := &countingReader{reader: io.TeeReader(source, hasher)}
	headerBytes := make([]byte, fixedHeaderLength)
	if err := readFullContext(ctx, counted, headerBytes); err != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import header is truncated")
	}
	header, err := parseHeader(headerBytes, request.Limits)
	if err != nil || header.PackageLength > request.Limits.MaximumPackageBytes {
		return evidencelifecycle.VerifiedImport{}, packageError("import header is invalid")
	}
	manifestBytes := make([]byte, header.ManifestLength)
	if err = readFullContext(ctx, counted, manifestBytes); err != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import manifest is truncated")
	}
	manifest, err := evidencelifecycle.DecodeExportManifest(manifestBytes)
	if err != nil || !manifestWithinLimits(manifest, header, request.Limits) {
		return evidencelifecycle.VerifiedImport{}, packageError("import manifest is invalid")
	}
	signatureBytes := make([]byte, header.SignatureLength)
	if err = readFullContext(ctx, counted, signatureBytes); err != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import signature is truncated")
	}
	signature, err := evidencelifecycle.DecodeDetachedSignature(signatureBytes)
	if err != nil || signature.ManifestDigest != manifest.ManifestDigest || signature.KeyID != manifest.SigningKeyID ||
		signature.KeyRevision != manifest.SigningKeyRevision {
		return evidencelifecycle.VerifiedImport{}, packageError("import signature is invalid")
	}
	now := worker.clock.Now()
	if !validWorkerTime(now) || !now.Before(request.Deadline) || now.Before(manifest.CreatedAt) ||
		!now.Before(manifest.ValidUntil) {
		return evidencelifecycle.VerifiedImport{}, packageError("import validity window is invalid")
	}
	if err = worker.signature.VerifyDetachedSignature(ctx, evidencelifecycle.VerifySignatureRequest{
		ManifestDigest: manifest.ManifestDigest, CanonicalBytes: manifestBytes, Signature: signature,
		TrustSnapshotDigest: worker.profile.TrustSnapshotDigest, RevocationDigest: worker.profile.RevocationDigest,
		At: now}); err != nil {
		return evidencelifecycle.VerifiedImport{}, packageError("import signature verification failed")
	}
	proof, err := worker.proof.VerifyExportProof(ctx, manifest)
	if err != nil || proof.CustodyReportDigest != manifest.CustodyReportDigest ||
		proof.AuditCheckpointDigest != manifest.AuditCheckpointDigest {
		return evidencelifecycle.VerifiedImport{}, packageError("import proof verification failed")
	}
	staged := make([]evidencelifecycle.StagedImportArtifact, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		value, stageErr := worker.readArtifact(ctx, counted, artifact, request.Limits)
		if stageErr != nil {
			return evidencelifecycle.VerifiedImport{}, stageErr
		}
		staged[index] = value
	}
	if counted.total != header.PackageLength {
		return evidencelifecycle.VerifiedImport{}, packageError("import package length is invalid")
	}
	if trailing, readErr := source.ReadByte(); readErr == nil || !errors.Is(readErr, io.EOF) || trailing != 0 {
		return evidencelifecycle.VerifiedImport{}, packageError("import package has trailing data")
	}
	packageDigest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if packageDigest != request.PackageDigest {
		return evidencelifecycle.VerifiedImport{}, packageError("import package digest is invalid")
	}
	return worker.buildVerified(request, header, manifest, signature, staged, proof, now, packageDigest)
}

func (worker *Worker) readArtifact(ctx context.Context, source io.Reader,
	artifact evidencelifecycle.ManifestArtifact, limits evidencelifecycle.PackageLimits) (
	evidencelifecycle.StagedImportArtifact, error) {
	fixed := make([]byte, 42)
	if err := readFullContext(ctx, source, fixed); err != nil {
		return evidencelifecycle.StagedImportArtifact{}, packageError("import artifact header is truncated")
	}
	digestText := "sha256:" + hex.EncodeToString(fixed[:32])
	length := int64(binary.BigEndian.Uint64(fixed[32:40]))
	mediaLength := int(binary.BigEndian.Uint16(fixed[40:42]))
	if digestText != artifact.Reference.Artifact.Digest || length != artifact.Reference.Artifact.Length ||
		length <= 0 || length > limits.MaximumArtifactBytes || mediaLength <= 0 || mediaLength > 255 {
		return evidencelifecycle.StagedImportArtifact{}, packageError("import artifact header is invalid")
	}
	media := make([]byte, mediaLength)
	if err := readFullContext(ctx, source, media); err != nil || string(media) != artifact.Reference.Artifact.MediaType {
		return evidencelifecycle.StagedImportArtifact{}, packageError("import artifact media type is invalid")
	}
	limited := &io.LimitedReader{R: source, N: length}
	artifactHasher := sha256.New()
	verified := &verificationReader{reader: io.TeeReader(limited, artifactHasher)}
	staged, err := worker.sink.StageArtifact(ctx, artifact.Ordinal, artifact.Reference, verified)
	if err != nil || limited.N != 0 || verified.total != length ||
		"sha256:"+hex.EncodeToString(artifactHasher.Sum(nil)) != artifact.Reference.Artifact.Digest ||
		staged.Ordinal != artifact.Ordinal || staged.ArtifactDigest != artifact.Reference.Artifact.Digest ||
		staged.Reference == "" || !validDigestText(staged.VerificationDigest) {
		return evidencelifecycle.StagedImportArtifact{}, packageError("import artifact verification failed")
	}
	return staged, nil
}

func parseHeader(value []byte, limits evidencelifecycle.PackageLimits) (evidencelifecycle.PackageHeader, error) {
	if len(value) != fixedHeaderLength || string(value[:9]) != evidencelifecycle.PackageMagic || value[9] != 1 ||
		value[10] != 0 || value[11] != 0 || value[12] != 0 {
		return evidencelifecycle.PackageHeader{}, packageError("import header prefix is invalid")
	}
	header := evidencelifecycle.PackageHeader{SchemaVersion: evidencelifecycle.PackageHeaderSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, Magic: evidencelifecycle.PackageMagic,
		PackageVersion: evidencelifecycle.PackageVersion, Compression: evidencelifecycle.NoCompression,
		PackageLength:   int64(binary.BigEndian.Uint64(value[13:21])),
		ManifestLength:  int64(binary.BigEndian.Uint32(value[21:25])),
		SignatureLength: int64(binary.BigEndian.Uint32(value[25:29])),
		ArtifactCount:   binary.BigEndian.Uint16(value[29:31]),
		HeaderDigest:    "sha256:" + hex.EncodeToString(value[31:])}
	if evidencelifecycle.ValidatePackageHeader(header) != nil || header.ManifestLength > limits.MaximumManifestBytes ||
		header.SignatureLength > limits.MaximumSignatureBytes || header.ArtifactCount > limits.MaximumArtifacts {
		return evidencelifecycle.PackageHeader{}, packageError("import header bounds are invalid")
	}
	return header, nil
}
