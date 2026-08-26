// Package deterministic implements a bounded text inspector that always
// renders retrieved text inside a canonical JSON data envelope.
package deterministic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
)

const MaximumSanitizedBytes = 64 << 20

type ContentReader interface {
	ReadContent(context.Context, retrievalguard.Source) ([]byte, error)
}
type SanitizedWriter interface {
	WriteSanitized(context.Context, []byte, string) (domain.ArtifactRef, error)
}

type Inspector struct {
	reader          ContentReader
	writer          SanitizedWriter
	inspectorDigest string
}

func New(reader ContentReader, writer SanitizedWriter, inspectorDigest string) (*Inspector, error) {
	if reader == nil || writer == nil || !validDigest(inspectorDigest) {
		return nil, errors.New("deterministic inspector configuration invalid")
	}
	return &Inspector{reader, writer, inspectorDigest}, nil
}

func (inspector *Inspector) Inspect(ctx context.Context, request retrievalguard.InspectionRequest) (retrievalguard.InspectionResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return retrievalguard.InspectionResult{}, contextError(ctx)
	}
	profileDigest, err := retrievalguard.ProfileBindingDigest(request.Profile)
	if err != nil || profileDigest != request.Profile.ProfileDigest ||
		request.Source.Trust != retrievalguard.UntrustedContent || !validDigest(request.IntentDigest) {
		return retrievalguard.InspectionResult{}, errors.New("inspection request invalid")
	}
	input, err := inspector.reader.ReadContent(ctx, request.Source)
	if err != nil {
		return retrievalguard.InspectionResult{}, err
	}
	if len(input) == 0 || int64(len(input)) != request.Source.Artifact.Length || int64(len(input)) > request.Profile.MaximumBytes || !utf8.Valid(input) || rawDigest(input) != request.Source.Artifact.Digest {
		return retrievalguard.InspectionResult{}, nil
	}
	sanitized, redactions := redact(string(input))
	sanitized = neutralizeActive(sanitized)
	findings := classify(string(input), redactions)
	envelope := struct {
		Trust        retrievalguard.TrustLabel `json:"trust"`
		SourceDigest string                    `json:"source_digest"`
		MediaType    string                    `json:"source_media_type"`
		Data         string                    `json:"data"`
	}{retrievalguard.UntrustedContent, request.Source.Artifact.Digest, request.Source.Artifact.MediaType, sanitized}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return retrievalguard.InspectionResult{}, err
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil || len(canonical) > MaximumSanitizedBytes || int64(len(canonical)) > request.Profile.MaximumBytes {
		return retrievalguard.InspectionResult{}, nil
	}
	artifact, err := inspector.writer.WriteSanitized(ctx, canonical, request.Source.Artifact.Classification)
	if err != nil {
		return retrievalguard.InspectionResult{}, err
	}
	if artifact.Digest != rawDigest(canonical) || artifact.MediaType != "application/json" || artifact.Classification != request.Source.Artifact.Classification || artifact.Length != int64(len(canonical)) {
		return retrievalguard.InspectionResult{}, nil
	}
	findingsDigest, err := retrievalguard.FindingsBindingDigest(findings)
	if err != nil {
		return retrievalguard.InspectionResult{}, err
	}
	return retrievalguard.InspectionResult{SourceDigest: request.Source.Artifact.Digest, SourceProvenanceDigest: request.Source.ProvenanceDigest, Sanitized: artifact,
		Trust: retrievalguard.UntrustedContent, Findings: findings, FindingsDigest: findingsDigest, RedactionCount: uint32(redactions), Complete: true, InspectorDigest: inspector.inspectorDigest}, nil
}

var patterns = []struct {
	code       retrievalguard.FindingCode
	expression *regexp.Regexp
}{
	{retrievalguard.InstructionLike, compile(`(?i)ignore\s+(all\s+)?(prior|previous)|system\s+prompt|follow\s+these\s+instructions`)},
	{retrievalguard.ScopeChangeAttempt, compile(`(?i)(change|switch|expand)\s+(the\s+)?(tenant|case|scope)`)},
	{retrievalguard.AuthorizationForgery, compile(`(?i)(grant|approve|authorize)\s+(access|action|request)|approval\s*[:=]\s*(yes|true)`)},
	{retrievalguard.CredentialRequest, compile(`(?i)(send|show|reveal|provide).{0,24}(credential|password|api[_ -]?key|token)`)},
	{retrievalguard.ToolDirective, compile(`(?i)(run|execute|invoke|call)\s+(the\s+)?(tool|command|shell)`)},
	{retrievalguard.ExfiltrationAttempt, compile(`(?i)(exfiltrate|upload|send).{0,32}(data|secret|credential|result).{0,16}(outside|external|remote|attacker)`)},
	{retrievalguard.ActiveContent, compile(`(?i)<\s*(script|iframe|object)|javascript\s*:|data\s*:\s*text/html`)},
	{retrievalguard.EncodedPayload, compile(`(?i)(base64|rot13|unicode escape|hex encoded)`)},
}
var secretPattern = compile(`(?i)(api[_ -]?key|password|access[_ -]?token|bearer)\s*[:= ]\s*[^\s,;"']{4,}`)
var digestPattern = compile(`^sha256:[0-9a-f]{64}$`)

func redact(input string) (string, int) {
	count := 0
	output := secretPattern.ReplaceAllStringFunc(input, func(match string) string {
		count++
		separator := strings.IndexAny(match, ":= ")
		if separator < 0 {
			return "[REDACTED]"
		}
		return match[:separator+1] + "[REDACTED]"
	})
	return output, count
}
func neutralizeActive(input string) string {
	replacer := strings.NewReplacer("&", `\u0026`, "<", `\u003c`, ">", `\u003e`)
	return replacer.Replace(input)
}
func classify(input string, redactions int) []retrievalguard.Finding {
	counts := map[retrievalguard.FindingCode]uint32{}
	for _, entry := range patterns {
		counts[entry.code] = uint32(len(entry.expression.FindAllStringIndex(input, -1)))
	}
	if redactions > 0 {
		counts[retrievalguard.SecretRedacted] = uint32(redactions)
	}
	codes := make([]string, 0, len(counts))
	for code, count := range counts {
		if count > 0 {
			codes = append(codes, string(code))
		}
	}
	sort.Strings(codes)
	result := make([]retrievalguard.Finding, 0, len(codes))
	for _, code := range codes {
		result = append(result, retrievalguard.Finding{Code: retrievalguard.FindingCode(code), Count: counts[retrievalguard.FindingCode(code)]})
	}
	return result
}
func compile(value string) *regexp.Regexp { return regexp.MustCompile(value) }
func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validDigest(value string) bool { return digestPattern.MatchString(value) }
func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context required")
	}
	return ctx.Err()
}

var _ retrievalguard.Inspector = (*Inspector)(nil)
