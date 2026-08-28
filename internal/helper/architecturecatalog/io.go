package architecturecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode: trailing value")
	}
	return nil
}

func readSource(root string, source Source) ([]byte, Source, error) {
	if source.Path == "" || filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path ||
		strings.HasPrefix(source.Path, "../") || source.Version == "" {
		return nil, Source{}, fmt.Errorf("invalid source declaration %q", source.Path)
	}
	path := filepath.Join(root, filepath.FromSlash(source.Path))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, Source{}, fmt.Errorf("source %s: %w", source.Path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > MaximumBytes {
		return nil, Source{}, fmt.Errorf("unsafe source %s", source.Path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Source{}, fmt.Errorf("source %s: %w", source.Path, err)
	}
	source.Digest = digest(data)
	return data, source, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonical(catalog Catalog) ([]byte, error) {
	catalog.CatalogDigest = ""
	data, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	catalog.CatalogDigest = digest(append([]byte("COH-ARCHITECTURE-CATALOG-V1\x00"), data...))
	data, err = json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > MaximumBytes {
		return nil, fmt.Errorf("catalog %s exceeds publication bound", catalog.CatalogType)
	}
	return data, nil
}
