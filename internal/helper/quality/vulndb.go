package quality

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	vulnDBLockSchema     = "coh.govulndb-lock/v1"
	vulnDBManifestSchema = "coh.govulndb-manifest/v1"
	maximumVulnDBFiles   = 20_000
	maximumVulnDBBytes   = 256 << 20
)

type VulnDBLock struct {
	SchemaVersion    string `json:"schema_version"`
	Source           string `json:"source"`
	ArchiveSHA256    string `json:"archive_sha256"`
	DatabaseModified string `json:"database_modified"`
	ManifestSHA256   string `json:"manifest_sha256"`
}

type VulnDBManifest struct {
	SchemaVersion    string     `json:"schema_version"`
	Source           string     `json:"source"`
	DatabaseModified string     `json:"database_modified"`
	Files            []Artifact `json:"files"`
}

type VulnDBVerification struct {
	SchemaVersion    string `json:"schema_version"`
	DatabaseID       string `json:"database_id"`
	DatabaseModified string `json:"database_modified"`
	ManifestSHA256   string `json:"manifest_sha256"`
	FileCount        int    `json:"file_count"`
}

var requiredVulnDBLock = VulnDBLock{
	SchemaVersion:    vulnDBLockSchema,
	Source:           "https://vuln.go.dev/vulndb.zip",
	ArchiveSHA256:    "6956c9eda20845fc540d08c38e22129b32effad51375ad3d6374fe1bed6d38cc",
	DatabaseModified: "2026-08-19T17:06:06Z",
	ManifestSHA256:   "a95e1ef286e8f04c1b14f899bc14b99ce2b357231e1abb2aae786ec168a5b75d",
}

func DecodeVulnDBLock(data []byte) (VulnDBLock, error) {
	var lock VulnDBLock
	if len(data) == 0 || len(data) > MaximumPolicySize || decodeStrict(data, &lock) != nil {
		return lock, qualityError(CodeInvalidInput, "vulndb_lock", "invalid vulnerability database lock", nil)
	}
	if lock != requiredVulnDBLock || !validDigest(lock.ArchiveSHA256) || !validDigest(lock.ManifestSHA256) {
		return lock, qualityError(CodeDenied, "vulndb_lock", "vulnerability database lock differs from the closed contract", nil)
	}
	if _, err := time.Parse(time.RFC3339, lock.DatabaseModified); err != nil {
		return lock, qualityError(CodeInvalidInput, "vulndb_lock.database_modified", "invalid database time", err)
	}
	return lock, nil
}

func GenerateVulnDBManifest(databaseURL, output string, lock VulnDBLock) error {
	root, err := localDatabaseRoot(databaseURL)
	if err != nil {
		return err
	}
	files, err := inventoryVulnDB(root)
	if err != nil {
		return err
	}
	manifest := VulnDBManifest{
		SchemaVersion: vulnDBManifestSchema, Source: lock.Source,
		DatabaseModified: lock.DatabaseModified, Files: files,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "vulndb_manifest", "cannot encode manifest", err)
	}
	return writeAtomic(output, append(encoded, '\n'))
}

func ExtractVulnDBArchive(archivePath, destination string, lock VulnDBLock) error {
	digest, err := DigestFile(archivePath)
	if err != nil || digest != lock.ArchiveSHA256 {
		return qualityError(CodeDenied, "vulndb_archive", "archive digest differs from lock", err)
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return qualityError(CodeDenied, "vulndb_archive", "destination must be a fresh real directory", err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return qualityError(CodeDenied, "vulndb_archive", "destination must be empty", err)
	}
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return qualityError(CodeInvalidInput, "vulndb_archive", "invalid ZIP archive", err)
	}
	defer archive.Close()
	if len(archive.File) == 0 || len(archive.File) > maximumVulnDBFiles+100 {
		return qualityError(CodeDenied, "vulndb_archive", "archive entry count is invalid", nil)
	}
	seen := map[string]bool{}
	var total uint64
	for _, entry := range archive.File {
		name := entry.Name
		clean := filepath.ToSlash(filepath.Clean(name))
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || clean != strings.TrimSuffix(name, "/") ||
			strings.HasPrefix(clean, "../") || seen[clean] || (clean != "ID" && clean != "index" && !strings.HasPrefix(clean, "ID/") && !strings.HasPrefix(clean, "index/")) {
			return qualityError(CodeDenied, "vulndb_archive", "unsafe or duplicate archive path", nil)
		}
		seen[clean] = true
		total += entry.UncompressedSize64
		if total > maximumVulnDBBytes || entry.UncompressedSize64 > maximumArtifactSize {
			return qualityError(CodeDenied, "vulndb_archive", "archive exceeds byte limits", nil)
		}
		path := filepath.Join(destination, filepath.FromSlash(clean))
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o750); err != nil {
				return qualityError(CodeToolFailure, "vulndb_archive", "cannot create directory", err)
			}
			continue
		}
		if !entry.Mode().IsRegular() {
			return qualityError(CodeDenied, "vulndb_archive", "non-regular archive member", nil)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return qualityError(CodeToolFailure, "vulndb_archive", "cannot create parent", err)
		}
		reader, err := entry.Open()
		if err != nil {
			return qualityError(CodeToolFailure, "vulndb_archive", "cannot open member", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			_ = reader.Close()
			return qualityError(CodeToolFailure, "vulndb_archive", "cannot create member", err)
		}
		written, copyErr := io.Copy(file, io.LimitReader(reader, int64(entry.UncompressedSize64)+1))
		closeErr := errors.Join(file.Sync(), file.Close(), reader.Close())
		if copyErr != nil || closeErr != nil || written != int64(entry.UncompressedSize64) {
			return qualityError(CodeToolFailure, "vulndb_archive", "cannot extract complete member", errors.Join(copyErr, closeErr))
		}
	}
	return verifyVulnDBIndexes(destination, lock.DatabaseModified)
}

func WriteVulnDBVerification(path string, verification VulnDBVerification) error {
	encoded, err := json.MarshalIndent(verification, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "vulndb", "cannot encode verification", err)
	}
	return writeAtomic(path, append(encoded, '\n'))
}

func VerifyVulnDB(databaseURL, manifestPath, manifestSHA string, lock VulnDBLock) (VulnDBVerification, error) {
	if manifestSHA != lock.ManifestSHA256 {
		return VulnDBVerification{}, qualityError(CodeDenied, "vulndb_manifest", "caller digest differs from lock", nil)
	}
	root, err := localDatabaseRoot(databaseURL)
	if err != nil {
		return VulnDBVerification{}, err
	}
	data, err := readBoundedRegular(manifestPath, 8<<20)
	if err != nil {
		return VulnDBVerification{}, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != lock.ManifestSHA256 {
		return VulnDBVerification{}, qualityError(CodeDenied, "vulndb_manifest", "raw manifest digest mismatch", nil)
	}
	var manifest VulnDBManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return VulnDBVerification{}, qualityError(CodeInvalidInput, "vulndb_manifest", "invalid manifest", err)
	}
	if manifest.SchemaVersion != vulnDBManifestSchema || manifest.Source != lock.Source ||
		manifest.DatabaseModified != lock.DatabaseModified || len(manifest.Files) == 0 {
		return VulnDBVerification{}, qualityError(CodeDenied, "vulndb_manifest", "manifest metadata differs from lock", nil)
	}
	actual, err := inventoryVulnDB(root)
	if err != nil {
		return VulnDBVerification{}, err
	}
	if !slices.Equal(manifest.Files, actual) {
		return VulnDBVerification{}, qualityError(CodeDenied, "vulndb_manifest", "database tree differs from manifest", nil)
	}
	if err := verifyVulnDBIndexes(root, lock.DatabaseModified); err != nil {
		return VulnDBVerification{}, err
	}
	return VulnDBVerification{
		SchemaVersion: "coh.govulndb-verification/v1", DatabaseID: "sha256:" + lock.ManifestSHA256,
		DatabaseModified: lock.DatabaseModified, ManifestSHA256: lock.ManifestSHA256,
		FileCount: len(actual),
	}, nil
}

func inventoryVulnDB(root string) ([]Artifact, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, qualityError(CodeDenied, "vulndb", "database root must be a real directory", err)
	}
	artifacts := make([]Artifact, 0)
	var total int64
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return qualityError(CodeDenied, "vulndb", "database contains a non-regular file", nil)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		artifact, err := digestArtifact(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return err
		}
		artifact.Path = filepath.ToSlash(relative)
		total += artifact.Length
		artifacts = append(artifacts, artifact)
		if len(artifacts) > maximumVulnDBFiles || total > maximumVulnDBBytes {
			return qualityError(CodeDenied, "vulndb", "database exceeds count or byte limit", nil)
		}
		return nil
	})
	if err != nil {
		return nil, qualityError(CodeDenied, "vulndb", "cannot inventory database", err)
	}
	slices.SortFunc(artifacts, func(a, b Artifact) int { return strings.Compare(a.Path, b.Path) })
	return artifacts, nil
}

func localDatabaseRoot(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !filepath.IsAbs(parsed.Path) {
		return "", qualityError(CodeDenied, "vulndb", "database must be a canonical absolute file URL", err)
	}
	decoded, err := url.PathUnescape(parsed.Path)
	if err != nil || (&url.URL{Scheme: "file", Path: decoded}).String() != raw {
		return "", qualityError(CodeDenied, "vulndb", "database URL is not canonical", err)
	}
	return filepath.Clean(decoded), nil
}

func verifyVulnDBIndexes(root, modified string) error {
	required := []string{"index/db.json", "index/modules.json", "index/vulns.json"}
	for _, path := range required {
		if _, err := digestPath(root, path); err != nil {
			return qualityError(CodeDenied, "vulndb", "required index is absent", err)
		}
	}
	var db struct {
		Modified string `json:"modified"`
	}
	if err := decodeJSONFile(filepath.Join(root, "index", "db.json"), &db); err != nil || db.Modified != modified {
		return qualityError(CodeDenied, "vulndb", "database timestamp mismatch", err)
	}
	var vulns []struct {
		ID string `json:"id"`
	}
	if err := decodeJSONFile(filepath.Join(root, "index", "vulns.json"), &vulns); err != nil {
		return qualityError(CodeDenied, "vulndb", "invalid vulnerability index", err)
	}
	var modules []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := decodeJSONFile(filepath.Join(root, "index", "modules.json"), &modules); err != nil {
		return qualityError(CodeDenied, "vulndb", "invalid module index", err)
	}
	vulnIDs, moduleIDs, fileIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, item := range vulns {
		vulnIDs[item.ID] = true
	}
	for _, module := range modules {
		for _, item := range module.Vulns {
			moduleIDs[item.ID] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "ID"))
	if err != nil {
		return qualityError(CodeDenied, "vulndb", "ID directory is absent", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "GO-") || !strings.HasSuffix(entry.Name(), ".json") || !entry.Type().IsRegular() {
			return qualityError(CodeDenied, "vulndb", "invalid ID entry", nil)
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		var record struct {
			ID string `json:"id"`
		}
		if err := decodeJSONFile(filepath.Join(root, "ID", entry.Name()), &record); err != nil || record.ID != id {
			return qualityError(CodeDenied, "vulndb", "ID record mismatch", err)
		}
		fileIDs[id] = true
	}
	if len(fileIDs) == 0 || !mapsEqual(vulnIDs, fileIDs) || !mapsEqual(moduleIDs, fileIDs) {
		return qualityError(CodeDenied, "vulndb", "index and ID sets differ", nil)
	}
	return nil
}

func decodeJSONFile(path string, destination any) error {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON is forbidden")
	}
	return nil
}

func mapsEqual(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
