package quality

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
)

const toolLockSchema = "coh.ci-tools/v1"

const maximumToolSize = 256 << 20

var requiredTools = []ToolSpec{
	{ID: "actionlint", Command: "actionlint", Package: "github.com/rhysd/actionlint/cmd/actionlint", Module: "github.com/rhysd/actionlint", Version: "v1.7.12", ModuleSum: "h1:vQ4GeJN86C0QH+gTUQcs8McmK62OLT3kmakPMtEWYnY=", GoModSum: "h1:krOUhujIsJusovkaYzQ/VNH8PFexjNKqU0q5XI/4w+g=", OriginHash: "914e7df21a07ef503a81201c76d2b11c789d3fca", Binaries: toolPins(
		[]string{"4bbdac8bf9cb5fb7760b5af2a5c6f84d0e020d63496227e684c8a735a3005206", "3f5957c509266704ebef355fce3593b38f95a63593cbe8e368ffea1d5b8fcb33", "fd44b7f20972cba7f7028f5e56909a36e4c8e7e2938629eae3f22eb4767335cf"},
		[]string{"54975825d5fbc90251a65624f22ed188c62b856f2f06fc96b70ebe90d18e3ac4", "a69a2ec6206fd4561aa4b00b78e7612b39eda09101bc62cf7fdf7aa6091439a7", "96116e6db3e967e5ae156de809a9045f38af26b8439b0037b982a51eeeb673f6"})},
	{ID: "gitleaks", Command: "gitleaks", Package: "github.com/zricethezav/gitleaks/v8", Module: "github.com/zricethezav/gitleaks/v8", Version: "v8.30.1", ModuleSum: "h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=", GoModSum: "h1:rTDwxRjufMKAkhTI/Mijd07nday1yOhf9qywjwz5Irw=", OriginHash: "8d1f98c7967eb1e79cb44ac6241a124e145d2165", Binaries: toolPins(
		[]string{"dfaf49ad50daaef7e07e3448cfd4763a6b2d2b10bf09a381b731567980f77f83", "caf9c18dda54d359eb7068c8597e2d778c07a04db48c4e3f49f2653d88302e73", "086b1c22a22c6fbc0f8b81642ad8ce1f7bed25f69c0b1cdc01a99a5c1d8e0171"},
		[]string{"9cbdd151ea71aba9316dfce52f6d53b85f7da5a5fa81ebddf5727df8206d67b4", "07f2cef677ca17d5d9599dac8b4fa510fb1fdb4be51f63dad47577cd4218282b", "83200f59cefad291a258fcb295d261d5f053109104c5f883aa7cd97e4b7689fa"})},
	{ID: "govulncheck", Command: "govulncheck", Package: "golang.org/x/vuln/cmd/govulncheck", Module: "golang.org/x/vuln", Version: "v1.7.0", ModuleSum: "h1:4MQBuhmXbz2uepNJrf3v+aaZLGDqw1JluwYboegA1qg=", GoModSum: "h1:Xw7zvU3e1bsCYYBXu+w4wcn2Kgn27f34WBCTw8LL5Us=", OriginHash: "617f44b718537dccdea1915395650e0529e3b72e", Binaries: toolPins(
		[]string{"bf424b5fc732d43a00e997bd433d6f61f0bfb7395d9944b09223cb1cd2d5e96c", "d3725b70cf83220fad293dab2c166ac549c44f0be73438cb4c6bda8dde05e3d4", "5c831c04a3e1e6186726a02e5a5545aecb849fb406addfc9e516ef0c7f2a095d"},
		[]string{"86a1ce50fba42862144777c862929a96c04266f878860f46a6500a65036c1cf4", "7a9c8c36f14c3baec576be74d48f70b84ea7eb85733e5befc4fcab65367d8b33", "772475ec287941eb788fd63e7a198fc91b97e3d3d87b6cd55256e927a7f2adce"})},
	{ID: "staticcheck", Command: "staticcheck", Package: "honnef.co/go/tools/cmd/staticcheck", Module: "honnef.co/go/tools", Version: "v0.7.0", ModuleSum: "h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=", GoModSum: "h1:pm29oPxeP3P82ISxZDgIYeOaf9ta6Pi0EWvCFoLG2vc=", OriginHash: "ff63afafc529279f454e02f1d060210bd4263951", Binaries: toolPins(
		[]string{"6720a191cd05c268e42a2e000e84104d9bb7f2b9f43655dbd35bab8dc078b917", "88c478e6d86c40bc8f6436aa09fb8df8075edf70acc2fb4a239a4a925e7a203b", "0daa5fe1c65d1ef1ceca3560de184585fd4c6513795c594f8b0c051cd1643fb6"}, nil)},
}

func toolPins(baseline, qualification []string) []ToolBinaryPin {
	platforms := [][2]string{{"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}}
	result := make([]ToolBinaryPin, 0, len(baseline)+len(qualification))
	for index, digest := range baseline {
		result = append(result, ToolBinaryPin{GoVersion: "1.26.7", GOOS: platforms[index][0], GOARCH: platforms[index][1], SHA256: digest})
	}
	for index, digest := range qualification {
		result = append(result, ToolBinaryPin{GoVersion: "1.27.0", GOOS: platforms[index][0], GOARCH: platforms[index][1], SHA256: digest})
	}
	return result
}

var requiredBinaryTools = []BinaryToolSpec{{
	ID: "shellcheck", Command: "shellcheck", Version: "0.11.0", License: "GPL-3.0-only (CI tool, not redistributed)",
	Platforms: []BinaryPlatformPin{
		{GOOS: "darwin", GOARCH: "arm64", Asset: "darwin.aarch64", ArchiveSHA256: "339b930feb1ea764467013cc1f72d09cd6b869ebf1013296ba9055ab2ffbd26f", BinarySHA256: "61c17246d69f012cd458ae82f244c46023dac75d1b69733ca1cc7d28fb270fd7"},
		{GOOS: "linux", GOARCH: "amd64", Asset: "linux.x86_64", ArchiveSHA256: "b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6", BinarySHA256: "4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b"},
		{GOOS: "linux", GOARCH: "arm64", Asset: "linux.aarch64", ArchiveSHA256: "68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc", BinarySHA256: "127f13925eadd52c341bca0ebaf9ab0dbd78c6468f30a8f262a528bf8de47546"},
	},
}}

func DecodeToolLock(data []byte) (ToolLock, string, error) {
	if len(data) == 0 || len(data) > MaximumPolicySize {
		return ToolLock{}, "", qualityError(CodeInvalidInput, "tool_lock", "tool lock size is invalid", nil)
	}
	var lock ToolLock
	if err := decodeStrict(data, &lock); err != nil {
		return ToolLock{}, "", qualityError(CodeInvalidInput, "tool_lock", "invalid tool lock JSON", err)
	}
	if lock.SchemaVersion != toolLockSchema || !reflect.DeepEqual(lock.Tools, requiredTools) || !reflect.DeepEqual(lock.BinaryTools, requiredBinaryTools) {
		return ToolLock{}, "", qualityError(CodeDenied, "tool_lock", "tool pins differ from the reviewed v1 lock", nil)
	}
	canonical, err := json.Marshal(lock)
	if err != nil {
		return ToolLock{}, "", qualityError(CodeToolFailure, "tool_lock", "cannot canonicalize tool lock", err)
	}
	sum := sha256.Sum256(canonical)
	return lock, hex.EncodeToString(sum[:]), nil
}

// VerifyTools authenticates the complete private tool directory. Go build
// metadata is provenance context; the locked whole-file digest is authority.
func VerifyTools(lock ToolLock, binDirectory, lane string) error {
	expectedNames := make([]string, 0, len(lock.Tools)+len(lock.BinaryTools))
	for _, tool := range lock.Tools {
		if lane == "go1.27" && tool.ID == "staticcheck" {
			continue
		}
		path := filepath.Join(binDirectory, tool.Command)
		expectedNames = append(expectedNames, tool.Command)
		digest, err := verifiedExecutableDigest(path)
		if err != nil {
			return qualityError(CodeDenied, "tools."+tool.ID, "tool binary is not a bounded regular executable", err)
		}
		expected, ok := selectedToolDigest(tool, lane, runtime.GOOS, runtime.GOARCH)
		if !ok || digest != expected {
			return qualityError(CodeDenied, "tools."+tool.ID, "whole-file binary digest does not match the lock", nil)
		}
		info, err := buildinfo.ReadFile(path)
		if err != nil {
			return qualityError(CodeToolFailure, "tools."+tool.ID, "cannot read installed tool provenance", err)
		}
		if info.Path != tool.Package || info.Main.Path != tool.Module || info.Main.Version != tool.Version || info.Main.Sum != tool.ModuleSum {
			return qualityError(CodeDenied, "tools."+tool.ID, "installed binary does not match the lock", nil)
		}
	}
	for _, tool := range lock.BinaryTools {
		expectedNames = append(expectedNames, tool.Command)
		var expected string
		for _, platform := range tool.Platforms {
			if platform.GOOS == runtime.GOOS && platform.GOARCH == runtime.GOARCH {
				expected = platform.BinarySHA256
			}
		}
		if expected == "" {
			return qualityError(CodeDenied, "tools."+tool.ID, "platform is not pinned", nil)
		}
		digest, err := verifiedExecutableDigest(filepath.Join(binDirectory, tool.Command))
		if err != nil {
			return qualityError(CodeDenied, "tools."+tool.ID, "binary is not a bounded regular executable", err)
		}
		if digest != expected {
			return qualityError(CodeDenied, "tools."+tool.ID, "binary digest does not match the lock", nil)
		}
	}
	slices.Sort(expectedNames)
	return verifyToolDirectoryNames(binDirectory, expectedNames)
}

func verifyToolDirectoryNames(binDirectory string, expectedNames []string) error {
	entries, err := os.ReadDir(binDirectory)
	if err != nil {
		return qualityError(CodeToolFailure, "tools", "cannot inspect private tool directory", err)
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		actualNames = append(actualNames, entry.Name())
	}
	slices.Sort(actualNames)
	if !slices.Equal(actualNames, expectedNames) {
		return qualityError(CodeDenied, "tools", "private tool directory contains missing or unexpected entries", nil)
	}
	return nil
}

func VerifyLockedTools(binDirectory, lane string) error {
	return VerifyTools(ToolLock{SchemaVersion: toolLockSchema, Tools: requiredTools, BinaryTools: requiredBinaryTools}, binDirectory, lane)
}

func selectedToolDigest(tool ToolSpec, lane, goos, goarch string) (string, bool) {
	version := "1.26.7"
	if lane == "go1.27" {
		version = "1.27.0"
	}
	for _, pin := range tool.Binaries {
		if pin.GoVersion == version && pin.GOOS == goos && pin.GOARCH == goarch {
			return pin.SHA256, true
		}
	}
	return "", false
}

func verifiedExecutableDigest(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&0o111 == 0 || before.Size() > maximumToolSize {
		return "", errors.New("executable must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", errors.New("executable identity changed before read")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumToolSize+1))
	if err != nil || len(data) > maximumToolSize {
		return "", errors.New("executable cannot be read within limit")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || int64(len(data)) != after.Size() {
		return "", errors.New("executable identity changed during read")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type moduleDownload struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Sum      string `json:"Sum"`
	GoModSum string `json:"GoModSum"`
	Origin   struct {
		Hash string `json:"Hash"`
	} `json:"Origin"`
}

// VerifyToolSources authenticates the module selected for each source-built
// tool before bootstrap compiles it in a private temporary GOMODCACHE.
func VerifyToolSources(ctx context.Context, lock ToolLock, goBinary, lane string) error {
	proxy, sumDB := os.Getenv("GOPROXY"), os.Getenv("GOSUMDB")
	if !((proxy == "https://proxy.golang.org" && sumDB == "sum.golang.org") || (proxy == "off" && sumDB == "off")) {
		return qualityError(CodeDenied, "tools.source_route", "tool acquisition route must be the reviewed proxy or offline", nil)
	}
	for _, tool := range lock.Tools {
		if lane == "go1.27" && tool.ID == "staticcheck" {
			continue
		}
		command := exec.CommandContext(ctx, goBinary, "mod", "download", "-json", tool.Module+"@"+tool.Version)
		command.Env = []string{
			"PATH=" + filepath.Dir(goBinary) + ":/usr/bin:/bin", "GOENV=off", "GOTELEMETRY=off", "GOTOOLCHAIN=local",
			"GOPROXY=" + proxy, "GOSUMDB=" + sumDB, "GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=",
			"GOMODCACHE=" + os.Getenv("GOMODCACHE"), "GOCACHE=" + os.Getenv("GOCACHE"),
			"GOPATH=" + os.Getenv("GOPATH"), "GOTMPDIR=" + os.Getenv("GOTMPDIR"), "TMPDIR=" + os.Getenv("GOTMPDIR"),
			"LANG=C", "LC_ALL=C",
		}
		var output boundedBuffer
		output.remaining = 2 << 20
		command.Stdout = &output
		command.Stderr = &output
		if err := command.Run(); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return contextQualityError(ctxErr, "tools."+tool.ID)
			}
			return qualityError(CodeToolFailure, "tools."+tool.ID, "cannot acquire locked module", err)
		}
		var downloaded moduleDownload
		decoder := json.NewDecoder(strings.NewReader(string(output.Bytes())))
		if err := decoder.Decode(&downloaded); err != nil {
			return qualityError(CodeToolFailure, "tools."+tool.ID, "invalid module download evidence", err)
		}
		if downloaded.Path != tool.Module || downloaded.Version != tool.Version || downloaded.Sum != tool.ModuleSum ||
			downloaded.GoModSum != tool.GoModSum || downloaded.Origin.Hash != tool.OriginHash {
			return qualityError(CodeDenied, "tools."+tool.ID, "module source provenance differs from the lock", nil)
		}
	}
	return nil
}
