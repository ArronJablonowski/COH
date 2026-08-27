// Package evidencepackage implements the pathless COHEVPKG1 streaming format.
package evidencepackage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

const fixedHeaderLength = 63

type SourceOpener interface {
	OpenArtifact(context.Context, domain.CaseRef, evidencelifecycle.EvidenceReference) (io.ReadCloser, error)
}

type EncodingReport struct {
	Header        evidencelifecycle.PackageHeader
	PackageDigest string
	PackageLength int64
}

func Encode(ctx context.Context, destination io.Writer, manifest evidencelifecycle.ExportManifest,
	signature evidencelifecycle.DetachedSignature, opener SourceOpener) (EncodingReport, error) {
	if ctx == nil || destination == nil || opener == nil || evidencelifecycle.ValidateExportManifest(manifest) != nil ||
		evidencelifecycle.ValidateDetachedSignature(signature) != nil || signature.ManifestDigest != manifest.ManifestDigest {
		return EncodingReport{}, errors.New("evidence package input is invalid")
	}
	manifestBytes, err := evidencelifecycle.CanonicalManifest(manifest)
	if err != nil {
		return EncodingReport{}, err
	}
	signatureBytes, err := evidencelifecycle.CanonicalDetachedSignature(signature)
	if err != nil {
		return EncodingReport{}, err
	}
	packageLength, err := encodedLength(manifest, len(manifestBytes), len(signatureBytes))
	if err != nil || packageLength > manifest.Limits.MaximumPackageBytes {
		return EncodingReport{}, errors.New("evidence package length is invalid")
	}
	header := evidencelifecycle.PackageHeader{SchemaVersion: evidencelifecycle.PackageHeaderSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, Magic: evidencelifecycle.PackageMagic,
		PackageVersion: evidencelifecycle.PackageVersion, Compression: evidencelifecycle.NoCompression,
		ManifestLength: int64(len(manifestBytes)), SignatureLength: int64(len(signatureBytes)),
		ArtifactCount: uint16(len(manifest.Artifacts)), PackageLength: packageLength}
	header.HeaderDigest, err = evidencelifecycle.HeaderBindingDigest(header)
	if err != nil || evidencelifecycle.ValidatePackageHeader(header) != nil {
		return EncodingReport{}, errors.New("evidence package header is invalid")
	}
	hasher := sha256.New()
	writer := io.MultiWriter(destination, hasher)
	if err = writeHeader(writer, header); err != nil {
		return EncodingReport{}, err
	}
	if err = writeAll(writer, manifestBytes); err != nil {
		return EncodingReport{}, err
	}
	if err = writeAll(writer, signatureBytes); err != nil {
		return EncodingReport{}, err
	}
	for _, artifact := range manifest.Artifacts {
		if err = writeArtifact(ctx, writer, opener, manifest.Case, artifact.Reference); err != nil {
			return EncodingReport{}, err
		}
	}
	return EncodingReport{Header: header, PackageDigest: sumDigest(hasher), PackageLength: packageLength}, nil
}

func encodedLength(manifest evidencelifecycle.ExportManifest, manifestLength, signatureLength int) (int64, error) {
	if manifestLength <= 0 || signatureLength <= 0 || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > math.MaxUint16 {
		return 0, errors.New("evidence package frame count is invalid")
	}
	total := int64(fixedHeaderLength + manifestLength + signatureLength)
	for _, artifact := range manifest.Artifacts {
		mediaLength := len(artifact.Reference.Artifact.MediaType)
		if mediaLength == 0 || mediaLength > math.MaxUint16 || artifact.Reference.Artifact.Length <= 0 ||
			total > math.MaxInt64-42-int64(mediaLength)-artifact.Reference.Artifact.Length {
			return 0, errors.New("evidence package frame length is invalid")
		}
		total += 42 + int64(mediaLength) + artifact.Reference.Artifact.Length
	}
	return total, nil
}

func writeHeader(writer io.Writer, value evidencelifecycle.PackageHeader) error {
	digestBytes, err := hex.DecodeString(value.HeaderDigest[len("sha256:"):])
	if err != nil || len(digestBytes) != sha256.Size {
		return errors.New("evidence package header digest is invalid")
	}
	buffer := make([]byte, fixedHeaderLength)
	copy(buffer[:9], []byte(evidencelifecycle.PackageMagic))
	buffer[9], buffer[10] = 1, 0
	binary.BigEndian.PutUint64(buffer[13:21], uint64(value.PackageLength))
	binary.BigEndian.PutUint32(buffer[21:25], uint32(value.ManifestLength))
	binary.BigEndian.PutUint32(buffer[25:29], uint32(value.SignatureLength))
	binary.BigEndian.PutUint16(buffer[29:31], value.ArtifactCount)
	copy(buffer[31:], digestBytes)
	return writeAll(writer, buffer)
}

func writeArtifact(ctx context.Context, writer io.Writer, opener SourceOpener,
	scope domain.CaseRef, reference evidencelifecycle.EvidenceReference) error {
	digestBytes, err := hex.DecodeString(reference.Artifact.Digest[len("sha256:"):])
	if err != nil || len(digestBytes) != sha256.Size {
		return errors.New("evidence package artifact digest is invalid")
	}
	media := []byte(reference.Artifact.MediaType)
	header := make([]byte, 42+len(media))
	copy(header[:32], digestBytes)
	binary.BigEndian.PutUint64(header[32:40], uint64(reference.Artifact.Length))
	binary.BigEndian.PutUint16(header[40:42], uint16(len(media)))
	copy(header[42:], media)
	if err = writeAll(writer, header); err != nil {
		return err
	}
	source, err := opener.OpenArtifact(ctx, scope, reference)
	if err != nil {
		return errors.New("evidence package artifact is unavailable")
	}
	defer source.Close()
	artifactHasher := sha256.New()
	limited := io.LimitReader(source, reference.Artifact.Length+1)
	written, err := copyContext(ctx, io.MultiWriter(writer, artifactHasher), limited)
	if err != nil || written != reference.Artifact.Length || sumDigest(artifactHasher) != reference.Artifact.Digest {
		return errors.New("evidence package artifact verification failed")
	}
	return nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func sumDigest(value hash.Hash) string { return "sha256:" + hex.EncodeToString(value.Sum(nil)) }
