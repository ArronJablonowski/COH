package supplychain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"errors"
	"io"
	"strings"
)

func verifyGoBinaryData(data []byte, packagePath, goVersion, target string) error {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return errorf(CodeDenied, "binary", "packaged executable has no valid Go build metadata", err)
	}
	if info.Path != packagePath || info.Main.Path != "github.com/ArronJablonowski/COH" || info.GoVersion != goVersion {
		return errorf(CodeDenied, "binary", "package or Go version differs from release policy", nil)
	}
	parts := strings.Split(target, "/")
	expected := map[string]string{"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0"}
	for _, setting := range info.Settings {
		if wanted, ok := expected[setting.Key]; ok {
			if setting.Value != wanted {
				return errorf(CodeDenied, "binary", "build setting differs from release policy", nil)
			}
			delete(expected, setting.Key)
		}
		if setting.Key == "vcs.modified" || setting.Key == "vcs.revision" || setting.Key == "vcs.time" {
			return errorf(CodeDenied, "binary", "non-reproducible VCS metadata is embedded", nil)
		}
	}
	if len(expected) != 0 {
		return errorf(CodeDenied, "binary", "required build settings are missing", nil)
	}
	return nil
}

func verifyPackagedBinaries(ctx context.Context, archive string, requirements []ArchiveRequirement, goVersion, target string) error {
	data, err := readStableRegular(archive, MaximumFileSize)
	if err != nil {
		return err
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return errorf(CodeInvalidInput, "binary", "cannot read release archive", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	index := 0
	for {
		if err := ctx.Err(); err != nil {
			return contextError(err, "binary")
		}
		header, readErr := tarReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || index >= len(requirements) || header.Name != requirements[index].Path {
			return errorf(CodeDenied, "binary", "archive order differs during binary verification", readErr)
		}
		entryData, readErr := io.ReadAll(io.LimitReader(tarReader, MaximumFileSize+1))
		if readErr != nil || int64(len(entryData)) != header.Size {
			return errorf(CodeInvalidInput, "binary", "cannot read packaged entry", readErr)
		}
		if requirements[index].Package != "" {
			if err := verifyGoBinaryData(entryData, requirements[index].Package, goVersion, target); err != nil {
				return err
			}
		}
		index++
	}
	if index != len(requirements) {
		return errorf(CodeDenied, "binary", "archive entries are incomplete", nil)
	}
	return nil
}
