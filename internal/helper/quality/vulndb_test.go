package quality

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVulnDBManifestSuccessTamperAndEmptyFallbackDenial(t *testing.T) {
	root, lock := tinyVulnDB(t)
	manifest := filepath.Join(t.TempDir(), "govulndb-manifest.json")
	if err := GenerateVulnDBManifest(fileURL(root), manifest, lock); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	lock.ManifestSHA256 = hex.EncodeToString(sum[:])
	verification, err := VerifyVulnDB(fileURL(root), manifest, lock.ManifestSHA256, lock)
	if err != nil || verification.FileCount != 4 {
		t.Fatalf("VerifyVulnDB() = %+v, %v", verification, err)
	}
	if err := os.WriteFile(filepath.Join(root, "ID", "GO-TEST-0001.json"), []byte(`{"id":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVulnDB(fileURL(root), manifest, lock.ManifestSHA256, lock); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered tree code = %q, want denied", CodeOf(err))
	}
	empty := t.TempDir()
	if _, err := VerifyVulnDB(fileURL(empty), manifest, lock.ManifestSHA256, lock); CodeOf(err) != CodeDenied {
		t.Fatalf("empty flat fallback code = %q, want denied", CodeOf(err))
	}
	if _, err := VerifyVulnDB("https://vuln.go.dev", manifest, lock.ManifestSHA256, lock); CodeOf(err) != CodeDenied {
		t.Fatalf("remote URL code = %q, want denied", CodeOf(err))
	}
}

func TestVulnDBRejectsExtraAndSymlink(t *testing.T) {
	for _, kind := range []string{"extra", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, lock := tinyVulnDB(t)
			manifest := filepath.Join(t.TempDir(), "govulndb-manifest.json")
			if err := GenerateVulnDBManifest(fileURL(root), manifest, lock); err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(manifest)
			sum := sha256.Sum256(data)
			lock.ManifestSHA256 = hex.EncodeToString(sum[:])
			if kind == "extra" {
				if err := os.WriteFile(filepath.Join(root, "extra.json"), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink(filepath.Join(root, "index", "db.json"), filepath.Join(root, "link.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyVulnDB(fileURL(root), manifest, lock.ManifestSHA256, lock); CodeOf(err) != CodeDenied {
				t.Fatalf("%s code = %q, want denied", kind, CodeOf(err))
			}
		})
	}
}

func TestGovulnSARIFDeniesFindingsAndProvenanceDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sarif")
	writeSARIF := func(results string, database string) {
		t.Helper()
		content := fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"govulncheck","semanticVersion":"v1.7.0","properties":{"scanner_name":"govulncheck","scanner_version":"v1.7.0","db":%q,"db_last_modified":"2026-08-19T17:06:06Z","scan_level":"symbol","scan_mode":"source"}}},"results":%s}]}`, database, results)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSARIF("[]", "file:///trusted")
	if err := VerifyGovulnSARIF(path, "file:///trusted", "2026-08-19T17:06:06Z"); err != nil {
		t.Fatal(err)
	}
	writeSARIF(`[{"ruleId":"GO-TEST"}]`, "file:///trusted")
	if err := VerifyGovulnSARIF(path, "file:///trusted", "2026-08-19T17:06:06Z"); CodeOf(err) != CodeDenied {
		t.Fatalf("finding code = %q, want denied", CodeOf(err))
	}
	writeSARIF("[]", "file:///other")
	if err := VerifyGovulnSARIF(path, "file:///trusted", "2026-08-19T17:06:06Z"); CodeOf(err) != CodeDenied {
		t.Fatalf("provenance code = %q, want denied", CodeOf(err))
	}
}

func TestExtractVulnDBArchiveRejectsAttackerShapedPaths(t *testing.T) {
	tests := []struct {
		name    string
		entries []zipFixtureEntry
	}{
		{name: "parent traversal", entries: []zipFixtureEntry{{name: "ID/../../outside.json", body: `{}`}}},
		{name: "absolute path", entries: []zipFixtureEntry{{name: "/ID/outside.json", body: `{}`}}},
		{name: "backslash path", entries: []zipFixtureEntry{{name: `ID\outside.json`, body: `{}`}}},
		{name: "symlink member", entries: []zipFixtureEntry{{name: "ID/link.json", body: "../index/db.json", mode: os.ModeSymlink | 0o777}}},
		{name: "duplicate normalized name", entries: []zipFixtureEntry{{name: "ID/", mode: os.ModeDir | 0o755}, {name: "ID", mode: os.ModeDir | 0o755}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive, lock := writeZipFixture(t, test.entries)
			destination := t.TempDir()
			outside := filepath.Join(filepath.Dir(destination), "outside.json")
			if err := ExtractVulnDBArchive(archive, destination, lock); CodeOf(err) != CodeDenied {
				t.Fatalf("ExtractVulnDBArchive() code = %q, want denied", CodeOf(err))
			}
			if _, err := os.Lstat(outside); !os.IsNotExist(err) {
				t.Fatalf("unsafe archive wrote outside destination: %v", err)
			}
		})
	}
}

func TestExtractVulnDBArchiveRejectsExpansionAndCorruption(t *testing.T) {
	t.Run("declared expansion exceeds member cap", func(t *testing.T) {
		archive, lock := writeZipFixture(t, []zipFixtureEntry{{name: "ID/GO-TEST-0001.json", body: `{}`}})
		data, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		central := bytes.Index(data, []byte("PK\x01\x02"))
		if central < 0 {
			t.Fatal("ZIP fixture has no central directory member")
		}
		binary.LittleEndian.PutUint32(data[central+24:central+28], uint32(maximumArtifactSize+1))
		lock = rewriteZipFixture(t, archive, data, lock)
		if err := ExtractVulnDBArchive(archive, t.TempDir(), lock); CodeOf(err) != CodeDenied {
			t.Fatalf("oversized member code = %q, want denied", CodeOf(err))
		}
	})

	t.Run("CRC mismatch", func(t *testing.T) {
		archive, lock := writeZipFixture(t, []zipFixtureEntry{{name: "index/db.json", body: `{"modified":"2026-08-19T17:06:06Z"}`}})
		data, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		local := bytes.Index(data, []byte("PK\x03\x04"))
		if local < 0 {
			t.Fatal("ZIP fixture has no local member")
		}
		nameLength := int(binary.LittleEndian.Uint16(data[local+26 : local+28]))
		extraLength := int(binary.LittleEndian.Uint16(data[local+28 : local+30]))
		contentOffset := local + 30 + nameLength + extraLength
		data[contentOffset] ^= 0xff
		lock = rewriteZipFixture(t, archive, data, lock)
		if err := ExtractVulnDBArchive(archive, t.TempDir(), lock); CodeOf(err) != CodeToolFailure {
			t.Fatalf("CRC mismatch code = %q, want tool_failure", CodeOf(err))
		}
	})

	t.Run("truncated central directory", func(t *testing.T) {
		archive, lock := writeZipFixture(t, validZipFixtureEntries())
		data, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		lock = rewriteZipFixture(t, archive, data[:len(data)-8], lock)
		if err := ExtractVulnDBArchive(archive, t.TempDir(), lock); CodeOf(err) != CodeInvalidInput {
			t.Fatalf("truncated archive code = %q, want invalid_input", CodeOf(err))
		}
	})
}

func TestExtractVulnDBArchiveRejectsMissingRequiredIndexes(t *testing.T) {
	for _, missing := range []string{"index/db.json", "index/modules.json", "index/vulns.json"} {
		t.Run(strings.TrimPrefix(missing, "index/"), func(t *testing.T) {
			entries := validZipFixtureEntries()
			filtered := entries[:0]
			for _, entry := range entries {
				if entry.name != missing {
					filtered = append(filtered, entry)
				}
			}
			archive, lock := writeZipFixture(t, filtered)
			if err := ExtractVulnDBArchive(archive, t.TempDir(), lock); CodeOf(err) != CodeDenied {
				t.Fatalf("missing %s code = %q, want denied", missing, CodeOf(err))
			}
		})
	}
}

func TestGovulnSARIFRejectsDuplicateAndIncompleteExecutionMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.sarif")
	valid := validSARIF("file:///trusted", "[]")
	tests := []struct {
		name    string
		content string
		code    ErrorCode
	}{
		{
			name: "duplicate scanner name hides earlier value",
			content: strings.Replace(valid, `"scanner_name":"govulncheck"`,
				`"scanner_name":"untrusted","scanner_name":"govulncheck"`, 1),
			code: CodeInvalidInput,
		},
		{
			name:    "duplicate top-level version",
			content: strings.Replace(valid, `"version":"2.1.0"`, `"version":"2.1.0","version":"2.1.0"`, 1),
			code:    CodeInvalidInput,
		},
		{
			name:    "missing semantic version",
			content: strings.Replace(valid, `,"semanticVersion":"v1.7.0"`, "", 1),
			code:    CodeDenied,
		},
		{
			name:    "missing database modification time",
			content: strings.Replace(valid, `,"db_last_modified":"2026-08-19T17:06:06Z"`, "", 1),
			code:    CodeDenied,
		},
		{
			name:    "missing scan mode",
			content: strings.Replace(valid, `,"scan_mode":"source"`, "", 1),
			code:    CodeDenied,
		},
		{
			name:    "missing explicit results",
			content: strings.Replace(valid, `,"results":[]`, "", 1),
			code:    CodeDenied,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyGovulnSARIF(path, "file:///trusted", "2026-08-19T17:06:06Z"); CodeOf(err) != test.code {
				t.Fatalf("VerifyGovulnSARIF() code = %q, want %q", CodeOf(err), test.code)
			}
		})
	}
}

type zipFixtureEntry struct {
	name string
	body string
	mode os.FileMode
}

func validZipFixtureEntries() []zipFixtureEntry {
	return []zipFixtureEntry{
		{name: "index/db.json", body: `{"modified":"2026-08-19T17:06:06Z"}`},
		{name: "index/vulns.json", body: `[{"id":"GO-TEST-0001"}]`},
		{name: "index/modules.json", body: `[{"path":"example.test/module","vulns":[{"id":"GO-TEST-0001"}]}]`},
		{name: "ID/GO-TEST-0001.json", body: `{"id":"GO-TEST-0001"}`},
	}
}

func writeZipFixture(t *testing.T, entries []zipFixtureEntry) (string, VulnDBLock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulndb.zip")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header.SetMode(mode)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	lock := VulnDBLock{DatabaseModified: "2026-08-19T17:06:06Z"}
	digest, err := DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock.ArchiveSHA256 = digest
	return path, lock
}

func rewriteZipFixture(t *testing.T, path string, data []byte, lock VulnDBLock) VulnDBLock {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lock.ArchiveSHA256 = digest
	return lock
}

func validSARIF(database, results string) string {
	return fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"govulncheck","semanticVersion":"v1.7.0","properties":{"scanner_name":"govulncheck","scanner_version":"v1.7.0","db":%q,"db_last_modified":"2026-08-19T17:06:06Z","scan_level":"symbol","scan_mode":"source"}}},"results":%s}]}`, database, results)
}

func tinyVulnDB(t *testing.T) (string, VulnDBLock) {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"index/db.json":        `{"modified":"2026-08-19T17:06:06Z"}`,
		"index/vulns.json":     `[{"id":"GO-TEST-0001"}]`,
		"index/modules.json":   `[{"path":"example.test/module","vulns":[{"id":"GO-TEST-0001"}]}]`,
		"ID/GO-TEST-0001.json": `{"id":"GO-TEST-0001"}`,
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, VulnDBLock{SchemaVersion: vulnDBLockSchema, Source: "https://vuln.go.dev/vulndb.zip", DatabaseModified: "2026-08-19T17:06:06Z"}
}

func fileURL(path string) string { return "file://" + filepath.ToSlash(path) }
