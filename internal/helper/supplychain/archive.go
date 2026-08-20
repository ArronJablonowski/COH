package supplychain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type ArchiveInput struct {
	Source  string
	Path    string
	Mode    int64
	Package string
}

type ArchiveEntry struct {
	Path   string
	Mode   int64
	SHA256 string
	Length int64
}

func CreateArchive(ctx context.Context, output string, inputs []ArchiveInput) ([]ArchiveEntry, error) {
	if len(inputs) == 0 || len(inputs) > 64 {
		return nil, errorf(CodeInvalidInput, "archive", "bounded archive inputs are required", nil)
	}
	if !slices.IsSortedFunc(inputs, func(a, b ArchiveInput) int { return strings.Compare(a.Path, b.Path) }) {
		return nil, errorf(CodeInvalidInput, "archive", "archive inputs must be sorted by path", nil)
	}
	var encoded bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&encoded, gzip.BestCompression)
	if err != nil {
		return nil, errorf(CodeToolFailure, "archive", "cannot initialize gzip writer", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	entries := make([]ArchiveEntry, 0, len(inputs))
	previous := ""
	var totalSize int64
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, contextError(err, "archive")
		}
		if !validArchivePath(input.Path) || input.Path <= previous || (input.Mode != 0o555 && input.Mode != 0o444) {
			return nil, errorf(CodeInvalidInput, "archive", "archive path, order, or mode is invalid", nil)
		}
		artifact, data, err := artifactFor(input.Source, filepath.Base(input.Path))
		if err != nil {
			return nil, err
		}
		if artifact.Length > MaximumFileSize-totalSize {
			return nil, errorf(CodeDenied, "archive", "uncompressed archive exceeds size limit", nil)
		}
		totalSize += artifact.Length
		header := &tar.Header{
			Name: input.Path, Mode: input.Mode, Size: int64(len(data)), Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Unix(0, 0).UTC(), ChangeTime: time.Unix(0, 0).UTC(),
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, errorf(CodeToolFailure, "archive", "cannot write tar header", err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			return nil, errorf(CodeToolFailure, "archive", "cannot write tar entry", err)
		}
		entries = append(entries, ArchiveEntry{Path: input.Path, Mode: input.Mode, SHA256: artifact.SHA256, Length: artifact.Length})
		previous = input.Path
	}
	if err := tarWriter.Close(); err != nil {
		return nil, errorf(CodeToolFailure, "archive", "cannot finalize tar stream", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, errorf(CodeToolFailure, "archive", "cannot finalize gzip stream", err)
	}
	if encoded.Len() > MaximumFileSize {
		return nil, errorf(CodeDenied, "archive", "archive exceeds size limit", nil)
	}
	if err := writeAtomicNoReplace(output, encoded.Bytes(), 0o444); err != nil {
		return nil, err
	}
	return entries, nil
}

func VerifyArchive(ctx context.Context, archive string, expected []ArchiveEntry) error {
	actual, err := InspectArchive(ctx, archive)
	if err != nil {
		return err
	}
	if !slices.Equal(actual, expected) {
		return errorf(CodeDenied, "archive", "archive entry set or digest differs", nil)
	}
	return nil
}

func InspectArchive(ctx context.Context, archive string) ([]ArchiveEntry, error) {
	data, err := readStableRegular(archive, MaximumFileSize)
	if err != nil {
		return nil, err
	}
	compressed := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, errorf(CodeInvalidInput, "archive", "invalid gzip stream", err)
	}
	gzipReader.Multistream(false)
	if !gzipReader.ModTime.IsZero() || gzipReader.Name != "" || gzipReader.Comment != "" || gzipReader.OS != 255 {
		return nil, errorf(CodeDenied, "archive", "gzip metadata is not reproducible", nil)
	}
	tarReader := tar.NewReader(gzipReader)
	actual := make([]ArchiveEntry, 0, 16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, contextError(err, "archive")
		}
		header, readErr := tarReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, errorf(CodeInvalidInput, "archive", "invalid tar stream", readErr)
		}
		if header.Typeflag != tar.TypeReg || !validArchivePath(header.Name) ||
			(header.Mode != 0o555 && header.Mode != 0o444) || header.Size < 0 || header.Size > MaximumFileSize ||
			header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" ||
			header.Format != tar.FormatPAX ||
			!header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.Equal(time.Unix(0, 0).UTC()) ||
			!header.ChangeTime.Equal(time.Unix(0, 0).UTC()) {
			return nil, errorf(CodeDenied, "archive", "unsafe or non-reproducible tar entry", nil)
		}
		for key, value := range header.PAXRecords {
			if (key != "atime" && key != "ctime") || value != "0" {
				return nil, errorf(CodeDenied, "archive", "tar entry contains non-canonical PAX metadata", nil)
			}
		}
		entryData, readErr := io.ReadAll(io.LimitReader(tarReader, MaximumFileSize+1))
		if readErr != nil || int64(len(entryData)) != header.Size {
			return nil, errorf(CodeInvalidInput, "archive", "truncated tar entry", readErr)
		}
		artifact := digestBytes(header.Name, entryData)
		actual = append(actual, ArchiveEntry{Path: header.Name, Mode: header.Mode, SHA256: artifact.SHA256, Length: artifact.Length})
	}
	trailing := make([]byte, 1)
	if count, readErr := gzipReader.Read(trailing); count != 0 || !errors.Is(readErr, io.EOF) {
		return nil, errorf(CodeDenied, "archive", "tar stream contains trailing payload", readErr)
	}
	if err := gzipReader.Close(); err != nil {
		return nil, errorf(CodeInvalidInput, "archive", "invalid gzip trailer", err)
	}
	if compressed.Len() != 0 {
		return nil, errorf(CodeDenied, "archive", "gzip stream contains trailing data", nil)
	}
	return actual, nil
}

func digestBytes(name string, data []byte) Artifact {
	sum := sha256.Sum256(data)
	return Artifact{Path: name, SHA256: hex.EncodeToString(sum[:]), Length: int64(len(data))}
}

func validArchivePath(value string) bool {
	clean := path.Clean(value)
	return value != "" && value == clean && !path.IsAbs(value) && clean != "." &&
		clean != ".." && !strings.HasPrefix(clean, "../") && !strings.Contains(value, "\\")
}
