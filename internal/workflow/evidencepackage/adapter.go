package evidencepackage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type QuarantineObject interface {
	io.Writer
	Commit(context.Context, EncodingReport, string, string) (string, error)
	Abandon(context.Context) error
}

type Quarantine interface {
	Create(context.Context, domain.CaseRef, string) (QuarantineObject, error)
	Open(context.Context, string) (io.ReadCloser, error)
	Recover(context.Context, domain.CaseRef, string) (evidencelifecycle.QuarantinedPackage, bool, error)
}

type Adapter struct {
	quarantine Quarantine
	sources    SourceOpener
}

func New(quarantine Quarantine, sources SourceOpener) (*Adapter, error) {
	if quarantine == nil || sources == nil {
		return nil, errors.New("evidence package dependencies are required")
	}
	return &Adapter{quarantine: quarantine, sources: sources}, nil
}

func (adapter *Adapter) BuildPackage(ctx context.Context,
	request evidencelifecycle.PackageBuildRequest) (evidencelifecycle.QuarantinedPackage, error) {
	if ctx == nil || request.Deadline.IsZero() || !request.Deadline.After(request.Manifest.CreatedAt) ||
		request.Evidence.Case != request.Manifest.Case ||
		request.Evidence.ArtifactSetDigest != request.Manifest.ArtifactSetDigest {
		return evidencelifecycle.QuarantinedPackage{}, errors.New("evidence package build request is invalid")
	}
	object, err := adapter.quarantine.Create(ctx, request.Manifest.Case, request.Manifest.ManifestID)
	if err != nil {
		return evidencelifecycle.QuarantinedPackage{}, errors.New("evidence package quarantine is unavailable")
	}
	committed := false
	defer func() {
		if !committed {
			_ = object.Abandon(context.WithoutCancel(ctx))
		}
	}()
	report, err := Encode(ctx, object, request.Manifest, request.Signature, adapter.sources)
	if err != nil {
		return evidencelifecycle.QuarantinedPackage{}, err
	}
	signatureDigest, err := evidencelifecycle.SignatureBindingDigest(request.Signature)
	if err != nil {
		return evidencelifecycle.QuarantinedPackage{}, err
	}
	reference, err := object.Commit(ctx, report, request.Manifest.ManifestDigest, signatureDigest)
	if err != nil {
		return evidencelifecycle.QuarantinedPackage{}, errors.New("evidence package commit is unavailable")
	}
	committed = true
	return evidencelifecycle.QuarantinedPackage{Reference: reference, Header: report.Header,
		HeaderDigest: report.Header.HeaderDigest, PackageDigest: report.PackageDigest,
		PackageLength: report.PackageLength, ManifestDigest: request.Manifest.ManifestDigest,
		SignatureDigest: signatureDigest}, nil
}

func (adapter *Adapter) RecoverPackage(ctx context.Context, scope domain.CaseRef,
	packageDigest string) (evidencelifecycle.QuarantinedPackage, bool, error) {
	if ctx == nil || packageDigest == "" {
		return evidencelifecycle.QuarantinedPackage{}, false, errors.New("evidence package recovery request is invalid")
	}
	return adapter.quarantine.Recover(ctx, scope, packageDigest)
}

func (adapter *Adapter) RecoverPackageProof(ctx context.Context, value evidencelifecycle.QuarantinedPackage,
	limits evidencelifecycle.PackageLimits) (evidencelifecycle.ExportManifest,
	evidencelifecycle.DetachedSignature, error) {
	if ctx == nil || value.Reference == "" || evidencelifecycle.ValidatePackageHeader(value.Header) != nil ||
		value.Header.ManifestLength > limits.MaximumManifestBytes ||
		value.Header.SignatureLength > limits.MaximumSignatureBytes {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package proof recovery request is invalid")
	}
	reader, err := adapter.quarantine.Open(ctx, value.Reference)
	if err != nil {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package quarantine is unavailable")
	}
	defer reader.Close()
	headerBytes := make([]byte, fixedHeaderLength)
	manifestBytes := make([]byte, value.Header.ManifestLength)
	signatureBytes := make([]byte, value.Header.SignatureLength)
	if err = readFullContext(ctx, reader, headerBytes); err != nil {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package header recovery failed")
	}
	if err = readFullContext(ctx, reader, manifestBytes); err != nil {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package manifest recovery failed")
	}
	if err = readFullContext(ctx, reader, signatureBytes); err != nil {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package signature recovery failed")
	}
	manifest, err := evidencelifecycle.DecodeExportManifest(manifestBytes)
	if err != nil || manifest.ManifestDigest != value.ManifestDigest ||
		value.Header.ArtifactCount != uint16(len(manifest.Artifacts)) {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package recovered manifest is invalid")
	}
	signature, err := evidencelifecycle.DecodeDetachedSignature(signatureBytes)
	signatureDigest, digestErr := evidencelifecycle.SignatureBindingDigest(signature)
	if err != nil || digestErr != nil || signatureDigest != value.SignatureDigest ||
		signature.ManifestDigest != manifest.ManifestDigest || signature.KeyID != manifest.SigningKeyID ||
		signature.KeyRevision != manifest.SigningKeyRevision {
		return evidencelifecycle.ExportManifest{}, evidencelifecycle.DetachedSignature{},
			errors.New("evidence package recovered signature is invalid")
	}
	return manifest, signature, nil
}

func (adapter *Adapter) VerifyPackage(ctx context.Context, value evidencelifecycle.QuarantinedPackage,
	limits evidencelifecycle.PackageLimits) error {
	if ctx == nil || value.Reference == "" || value.PackageLength <= 0 ||
		value.PackageLength > limits.MaximumPackageBytes || value.Header.PackageLength != value.PackageLength ||
		value.Header.HeaderDigest != value.HeaderDigest || evidencelifecycle.ValidatePackageHeader(value.Header) != nil {
		return errors.New("evidence package verification request is invalid")
	}
	reader, err := adapter.quarantine.Open(ctx, value.Reference)
	if err != nil {
		return errors.New("evidence package quarantine is unavailable")
	}
	defer reader.Close()
	expectedHeader := make([]byte, fixedHeaderLength)
	headerBuffer := bytesWriter{value: expectedHeader}
	if err = writeHeader(&headerBuffer, value.Header); err != nil {
		return err
	}
	actualHeader := make([]byte, fixedHeaderLength)
	if _, err = io.ReadFull(reader, actualHeader); err != nil || !equalBytes(actualHeader, expectedHeader) {
		return errors.New("evidence package header verification failed")
	}
	hasher := sha256.New()
	_, _ = hasher.Write(actualHeader)
	remaining := value.PackageLength - fixedHeaderLength
	written, err := copyContext(ctx, hasher, io.LimitReader(reader, remaining+1))
	if err != nil || written != remaining || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != value.PackageDigest {
		return errors.New("evidence package digest verification failed")
	}
	return nil
}

type bytesWriter struct {
	value  []byte
	offset int
}

func (writer *bytesWriter) Write(value []byte) (int, error) {
	if writer.offset+len(value) > len(writer.value) {
		return 0, io.ErrShortWrite
	}
	copy(writer.value[writer.offset:], value)
	writer.offset += len(value)
	return len(value), nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

var _ evidencelifecycle.PackageWriter = (*Adapter)(nil)
