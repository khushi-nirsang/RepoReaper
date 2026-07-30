package detector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
)

type Detector interface {
	ID() string
	Name() string
	Description() string
	Severity() model.Severity
	Keywords() []string
	Category() string
	Remediation() []string
	Signature() string
	Find(content []byte) []Match
}

type Match struct {
	DetectorID  string
	Value       string
	ValueLength int
	Redacted    string
	Fingerprint string
	Short       string
	Line        int
	Confidence  model.Confidence
	Location    string
	Decoder     string
}

// ResultSemanticsVersion changes whenever shared match sanitization or other
// result-shaping behavior changes. Persistent caches include it in their
// semantic namespace.
const ResultSemanticsVersion = "detector-result-redaction-v1"

// DetectionSemanticsVersion covers shared matching behavior that is not part
// of an individual regex: placeholder/source suppression and capture rules.
// Scan reports bind remediation verification to this plus content expansion
// semantics so a changed shared pipeline cannot support a false absence claim.
const DetectionSemanticsVersion = "detector-matching-v2"

func ScanSignature(ruleSignature, contentSemantics string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "reporeaper-scan-signature-v1\x00%s\x00%s\x00%s\x00", ruleSignature, contentSemantics, DetectionSemanticsVersion)
	return hex.EncodeToString(h.Sum(nil))
}

const capturedValueReplacement = "[REDACTED-CAPTURE]"

// CaptureScrubber identifies captured values either from their transient raw
// value or from the fingerprint and length retained by a persistent cache.
// The latter lets cache hits scrub repository evidence without persisting a
// reversible copy of the captured value.
type CaptureScrubber struct {
	raw      []string
	byLength map[int]map[[sha256.Size]byte]struct{}
}

// NewCaptureScrubber validates the match identity metadata and prepares an
// exact-value scrubber. Raw values are retained only in this in-memory helper.
func NewCaptureScrubber(matches []Match) (CaptureScrubber, bool) {
	scrubber := CaptureScrubber{byLength: map[int]map[[sha256.Size]byte]struct{}{}}
	rawSeen := map[string]bool{}
	valid := true
	for _, match := range matches {
		length := match.ValueLength
		if match.Value != "" {
			full, short := fingerprint.SHA256(match.Value)
			if full != match.Fingerprint || short != match.Short {
				valid = false
			}
			length = len(match.Value)
			if !rawSeen[match.Value] {
				rawSeen[match.Value] = true
				scrubber.raw = append(scrubber.raw, match.Value)
			}
		}
		if length < 1 || length > 1<<30 || len(match.Fingerprint) != 64 ||
			strings.ToLower(match.Fingerprint) != match.Fingerprint ||
			match.Short != match.Fingerprint[:min(12, len(match.Fingerprint))] {
			valid = false
			continue
		}
		decoded, err := hex.DecodeString(match.Fingerprint)
		if err != nil || len(decoded) != sha256.Size {
			valid = false
			continue
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		// A transient raw value can be located directly without hashing every
		// same-length window. Fingerprint window scans are reserved for
		// cache-hit proofs where the raw value is deliberately unavailable.
		if match.Value == "" {
			if scrubber.byLength[length] == nil {
				scrubber.byLength[length] = map[[sha256.Size]byte]struct{}{}
			}
			scrubber.byLength[length][digest] = struct{}{}
		}
	}
	sort.Slice(scrubber.raw, func(i, j int) bool {
		if len(scrubber.raw[i]) != len(scrubber.raw[j]) {
			return len(scrubber.raw[i]) > len(scrubber.raw[j])
		}
		return scrubber.raw[i] < scrubber.raw[j]
	})
	return scrubber, valid
}

type captureSpan struct {
	start int
	end   int
}

// Contains reports whether text contains any complete captured value.
func (s CaptureScrubber) Contains(text string) bool {
	for _, raw := range s.raw {
		if strings.Contains(text, raw) {
			return true
		}
	}
	for length, fingerprints := range s.byLength {
		if length > len(text) {
			continue
		}
		for offset := 0; offset+length <= len(text); offset++ {
			sum := sha256.Sum256([]byte(text[offset : offset+length]))
			if _, ok := fingerprints[sum]; ok {
				return true
			}
		}
	}
	return false
}

// Scrub replaces every exact captured-value occurrence with a fixed marker.
// If that marker itself happens to be a captured value, the result is emptied
// rather than returning unsafe text.
func (s CaptureScrubber) Scrub(text string) string {
	var spans []captureSpan
	for _, raw := range s.raw {
		for offset := 0; offset+len(raw) <= len(text); {
			index := strings.Index(text[offset:], raw)
			if index < 0 {
				break
			}
			start := offset + index
			spans = append(spans, captureSpan{start: start, end: start + len(raw)})
			offset = start + 1
		}
	}
	for length, fingerprints := range s.byLength {
		if length > len(text) {
			continue
		}
		for offset := 0; offset+length <= len(text); offset++ {
			sum := sha256.Sum256([]byte(text[offset : offset+length]))
			if _, ok := fingerprints[sum]; ok {
				spans = append(spans, captureSpan{start: offset, end: offset + length})
			}
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	merged := spans[:0]
	for _, span := range spans {
		if len(merged) == 0 || span.start > merged[len(merged)-1].end {
			merged = append(merged, span)
			continue
		}
		if span.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = span.end
		}
	}
	var output strings.Builder
	output.Grow(len(text))
	cursor := 0
	for _, span := range merged {
		output.WriteString(text[cursor:span.start])
		output.WriteString(capturedValueReplacement)
		cursor = span.end
	}
	output.WriteString(text[cursor:])
	scrubbed := output.String()
	if s.Contains(scrubbed) {
		return ""
	}
	return scrubbed
}

// SanitizeMatches scrubs every content-derived text field against every
// captured value, including captures made by another detector.
func SanitizeMatches(matches []Match) ([]Match, CaptureScrubber, bool) {
	sanitized := append([]Match(nil), matches...)
	scrubber, valid := NewCaptureScrubber(sanitized)
	for index := range sanitized {
		if sanitized[index].Value != "" {
			sanitized[index].ValueLength = len(sanitized[index].Value)
		}
		if scrubber.Contains(sanitized[index].DetectorID) {
			// Detector identity is required to reconstruct a finding and cannot
			// be altered safely. Such a result remains usable in memory but is
			// not safe for persistent caching.
			valid = false
		}
		sanitized[index].Redacted = scrubber.Scrub(sanitized[index].Redacted)
		sanitized[index].Location = scrubber.Scrub(sanitized[index].Location)
		sanitized[index].Decoder = scrubber.Scrub(sanitized[index].Decoder)
		if sanitized[index].Redacted == "" {
			sanitized[index].Redacted = scrubber.Scrub("[REDACTED]")
			if sanitized[index].Redacted == "" {
				valid = false
			}
		}
	}
	return sanitized, scrubber, valid
}

type RegexDetector struct {
	id, name, description, category string
	severity                        model.Severity
	keywords, remediation           []string
	re                              *regexp.Regexp
	minEntropy                      float64
	redact                          func(string) string
	validatorID                     string
	validate                        func(matched, secret string) bool
}

func NewRegex(id, name, desc, category string, sev model.Severity, keywords []string, pattern string, minEntropy float64, redactor func(string) string, remediation []string) (*RegexDetector, error) {
	return NewValidatedRegex(id, name, desc, category, sev, keywords, pattern, minEntropy, redactor, remediation, "", nil)
}

// NewValidatedRegex combines regex candidate generation with an offline
// structural validator. Validators must not make network requests.
func NewValidatedRegex(id, name, desc, category string, sev model.Severity, keywords []string, pattern string, minEntropy float64, redactor func(string) string, remediation []string, validatorID string, validator func(matched, secret string) bool) (*RegexDetector, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &RegexDetector{
		id: id, name: name, description: desc, category: category, severity: sev,
		keywords: keywords, re: re, minEntropy: minEntropy, redact: redactor,
		remediation: remediation, validatorID: validatorID, validate: validator,
	}, nil
}

func (d *RegexDetector) ID() string               { return d.id }
func (d *RegexDetector) Name() string             { return d.name }
func (d *RegexDetector) Description() string      { return d.description }
func (d *RegexDetector) Severity() model.Severity { return d.severity }
func (d *RegexDetector) Keywords() []string       { return d.keywords }
func (d *RegexDetector) Category() string         { return d.category }
func (d *RegexDetector) Remediation() []string    { return append([]string{}, d.remediation...) }
func (d *RegexDetector) Signature() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "reporeaper-regex-detector-v2\x00%s\x00%s\x00%.17g\x00%s\x00", d.id, d.re.String(), d.minEntropy, d.validatorID)
	for _, keyword := range d.keywords {
		_, _ = fmt.Fprintf(h, "%s\x00", strings.ToLower(keyword))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (d *RegexDetector) Find(content []byte) []Match {
	return d.findString(string(content))
}

type PreparedText struct {
	text  string
	lower string
}

// PrepareText lets coordinators convert and case-fold a payload once for the
// entire registry rather than allocating one copy per detector.
func PrepareText(content []byte) PreparedText {
	text := string(content)
	return PreparedText{text: text, lower: strings.ToLower(text)}
}

// FindPrepared uses the shared text representation when the detector supports
// it. The fallback preserves support for other Detector implementations.
func FindPrepared(active Detector, prepared PreparedText) []Match {
	if stringDetector, ok := active.(interface{ findPrepared(PreparedText) []Match }); ok {
		return stringDetector.findPrepared(prepared)
	}
	return active.Find([]byte(prepared.text))
}

func (d *RegexDetector) findString(text string) []Match {
	return d.findPrepared(PreparedText{text: text, lower: strings.ToLower(text)})
}

func (d *RegexDetector) findPrepared(prepared PreparedText) []Match {
	text, lower := prepared.text, prepared.lower
	if len(d.keywords) > 0 {
		ok := false
		for _, kw := range d.keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}
	}
	var out []Match
	for _, loc := range d.re.FindAllStringSubmatchIndex(text, -1) {
		matched := text[loc[0]:loc[1]]
		secret := matched
		if len(loc) >= 4 && loc[2] >= 0 {
			secret = text[loc[2]:loc[3]]
		}
		if suppress(secret) || looksLikeDetectorSource(matched) || (d.minEntropy > 0 && Entropy(secret) < d.minEntropy) {
			continue
		}
		if d.validate != nil && !d.validate(matched, secret) {
			continue
		}
		full, short := fingerprint.SHA256(secret)
		red := tokenRedactor(secret)
		if d.redact != nil {
			red = d.redact(matched)
		}
		out = append(out, Match{DetectorID: d.id, Value: secret, ValueLength: len(secret), Redacted: red, Fingerprint: full, Short: short, Line: lineNumber(text, loc[0]), Confidence: model.ConfidenceHigh})
	}
	return out
}

func Registry(custom []Detector, disabled map[string]bool) []Detector {
	var all []Detector
	add := func(d Detector, err error) {
		if err == nil && !disabled[d.ID()] {
			all = append(all, d)
		}
	}
	rem := GenericRemediation()
	add(NewRegex("aws-access-key-id", "AWS access key identifier", "AWS access key identifiers can identify exposed IAM credentials.", "cloud", model.SeverityHigh, []string{"AKIA", "ASIA", "aws"}, `\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b`, 0, func(s string) string { return s[:4] + strings.Repeat("*", 12) + s[len(s)-4:] }, rem))
	add(NewRegex("aws-secret-access-key", "AWS secret access key", "AWS secret-access-key assignment with explicit configuration context.", "cloud", model.SeverityCritical, []string{"aws_secret_access_key", "secret_access_key"}, `(?i)(?:^|[^A-Za-z0-9])["']?(?:aws[_-])?secret[_-]access[_-]key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`, 3.5, redactAssignment, rem))
	add(NewRegex("github-token", "GitHub token", "GitHub classic, fine-grained, OAuth, and app tokens.", "scm", model.SeverityCritical, []string{"ghp_", "github", "gho_", "ghu_", "ghs_", "github_pat_"}, `(?:^|[^A-Za-z0-9_])((?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,}))(?:[^A-Za-z0-9_]|$)`, 3.2, tokenRedactor, rem))
	add(NewRegex("gitlab-token", "GitLab token", "GitLab access, OAuth, deploy, runner, job, trigger, feed, agent, workspace, SCIM, and feature-flag tokens.", "scm", model.SeverityCritical, []string{"glpat-", "gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glwt-", "glsoat-", "glffct-"}, `(?:^|[^A-Za-z0-9_])((?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_\-]{20,})(?:[^A-Za-z0-9_\-]|$)`, 3.2, tokenRedactor, rem))
	add(NewRegex("slack-token", "Slack token or webhook", "Slack API tokens, rotating credentials, and webhook URLs.", "chat", model.SeverityCritical, []string{"xoxb-", "xoxp-", "xapp-", "xwfp-", "xoxe-", "xoxe.", "hooks.slack.com"}, `(?:^|[^A-Za-z0-9_])((?:(?:xox[baprs]|xapp|xwfp)-[A-Za-z0-9\-]{20,}|xoxe(?:\.xox[bp])?-[A-Za-z0-9\-]{20,}|https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/]{20,}))(?:[^A-Za-z0-9/._\-]|$)`, 3.0, tokenRedactor, rem))
	add(NewRegex("google-api-key", "Google API key", "Google API key-like values.", "cloud", model.SeverityHigh, []string{"AIza", "google"}, `\bAIza[0-9A-Za-z_\-]{35}\b`, 3.0, tokenRedactor, rem))
	add(NewRegex("stripe-key", "Stripe API key", "Stripe secret, restricted, and webhook signing keys.", "payment", model.SeverityCritical, []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "stripe"}, `\b(?:[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b`, 3.0, tokenRedactor, rem))
	add(NewRegex("twilio-credential", "Twilio Account SID", "Twilio Account SID identifier; this is not an authentication secret by itself.", "communications", model.SeverityInfo, []string{"twilio", "AC"}, `\bAC[a-fA-F0-9]{32}\b`, 0, tokenRedactor, rem))
	add(NewRegex("twilio-auth-token", "Twilio authentication secret", "Twilio Auth Token or API-key secret in an explicit assignment.", "communications", model.SeverityCritical, []string{"twilio", "auth_token", "api_key_secret", "twilio_auth_token"}, `(?i)(?:^|[^A-Za-z0-9])["']?(?:twilio[_-])?(?:auth[_-]?token|api[_-]?key[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{24,})["']?`, 3.0, redactAssignment, rem))
	add(NewRegex("sendgrid-api-key", "SendGrid API key", "SendGrid API key-like values.", "email", model.SeverityCritical, []string{"SG.", "sendgrid"}, `(?:^|[^A-Za-z0-9_.\-])(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})(?:[^A-Za-z0-9_.\-]|$)`, 3.0, tokenRedactor, rem))
	add(NewRegex("npm-token", "npm token", "npm automation or access token.", "package", model.SeverityCritical, []string{"npm_", "//registry.npmjs.org"}, `\bnpm_[A-Za-z0-9]{20,}\b`, 3.0, tokenRedactor, rem))
	add(NewRegex("pypi-token", "PyPI token", "PyPI API token.", "package", model.SeverityCritical, []string{"pypi-", "__token__"}, `(?:^|[^A-Za-z0-9_])((?:pypi-)[A-Za-z0-9_\-]{20,})(?:[^A-Za-z0-9_\-]|$)`, 3.0, tokenRedactor, rem))
	add(NewValidatedRegex("jwt", "Structurally valid JWT", "Three-part JSON Web Token with decodable JSON header and claims.", "token", model.SeverityMedium, []string{"eyJ"}, `\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`, 3.2, tokenRedactor, rem, "jwt-json-v1", validateJWT))
	add(NewRegex("generic-bearer-token", "Generic bearer token", "Bearer token assignment or header.", "token", model.SeverityHigh, []string{"bearer"}, `(?i)\bbearer\s+([A-Za-z0-9._\-]{24,})(?:[^A-Za-z0-9._\-]|$)`, 3.0, redactBearer, rem))
	add(NewRegex("generic-api-key", "Generic API key", "Keyword-bound generic API key assignment.", "token", model.SeverityMedium, []string{"api_key", "api-key", "apikey", "access_token", "access-token", "secret"}, `(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9._\-]{24,})["']?`, 3.2, redactAssignment, rem))
	add(NewRegex("postgres-connection-string", "PostgreSQL connection string", "PostgreSQL URI containing credentials.", "database", model.SeverityHigh, []string{"postgres://", "postgresql://"}, `\bpostgres(?:ql)?://[^\s"'<>:@]+:([^\s"'<>@]+)@[^\s"'<>]+`, 2.5, redactURLPassword, rem))
	add(NewRegex("mysql-connection-string", "MySQL connection string", "MySQL URI containing credentials.", "database", model.SeverityHigh, []string{"mysql://"}, `\bmysql://[^\s"'<>:@]+:([^\s"'<>@]+)@[^\s"'<>]+`, 2.5, redactURLPassword, rem))
	add(NewRegex("mongodb-connection-string", "MongoDB connection string", "MongoDB URI containing credentials.", "database", model.SeverityHigh, []string{"mongodb://", "mongodb+srv://"}, `\bmongodb(?:\+srv)?://[^\s"'<>:@]+:([^\s"'<>@]+)@[^\s"'<>]+`, 2.5, redactURLPassword, rem))
	add(NewRegex("redis-credential-url", "Redis credential URL", "Redis URI containing credentials.", "database", model.SeverityHigh, []string{"redis://"}, `\bredis://(?:[^\s"'<>:@]+:)?([^\s"'<>@]+)@[^\s"'<>]+`, 2.5, redactURLPassword, rem))
	add(NewRegex("basic-auth-url", "Basic-auth URL", "URL containing username and password.", "network", model.SeverityHigh, []string{"://"}, `\bhttps?://[^/\s"'<>:@]+:([^/\s"'<>@]+)@[^/\s"'<>]+`, 2.5, redactURLPassword, rem))
	add(NewValidatedRegex("pem-private-key", "PEM private key", "PEM private-key block with matching armor and decodable non-empty body.", "private-key", model.SeverityCritical, []string{"BEGIN", "PRIVATE KEY"}, `-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----`, 0, func(string) string { return "-----BEGIN PRIVATE KEY----- [REDACTED]" }, rem, "pem-private-key-v1", validatePEMPrivateKey))
	add(NewValidatedRegex("openssh-private-key", "OpenSSH private key", "OpenSSH private-key block with matching armor and decodable non-empty body.", "private-key", model.SeverityCritical, []string{"OPENSSH PRIVATE KEY"}, `-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----`, 0, func(string) string { return "-----BEGIN OPENSSH PRIVATE KEY----- [REDACTED]" }, rem, "pem-openssh-v1", validatePEMPrivateKey))
	add(NewValidatedRegex("pgp-private-key", "PGP private key", "PGP private-key block with matching armor and decodable non-empty body.", "private-key", model.SeverityCritical, []string{"PGP PRIVATE KEY"}, `-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----`, 0, func(string) string { return "-----BEGIN PGP PRIVATE KEY BLOCK----- [REDACTED]" }, rem, "pem-pgp-v1", validatePEMPrivateKey))
	kubernetes := NewKubernetesSecretDetector(rem)
	if !disabled[kubernetes.ID()] {
		all = append(all, kubernetes)
	}
	add(NewValidatedRegex("docker-registry-credential", "Docker registry credential", "Docker auth field containing a decodable username and password.", "container", model.SeverityHigh, []string{"auths", "\"auth\""}, `"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"`, 3.0, redactAssignment, rem, "docker-basic-auth-v1", validateDockerAuth))
	add(NewRegex("env-password", "Environment password assignment", "Password-like environment assignment.", "password", model.SeverityHigh, []string{"password", "passwd", "pwd"}, `(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^"'\s]{10,})["']?`, 2.5, redactAssignment, rem))
	add(NewValidatedRegex("service-account-json", "Cloud service account credential", "Cloud service-account JSON containing a private-key block.", "cloud", model.SeverityCritical, []string{"private_key", "client_email", "service_account"}, `"private_key"\s*:\s*"((?:\\.|[^"\\]){20,})"`, 0, func(string) string { return `"private_key":"[REDACTED]"` }, rem, "json-private-key-v1", validateJSONPrivateKey))
	add(NewRegex("high-entropy-secret", "High entropy unknown secret", "Keyword-bound high entropy unknown value.", "token", model.SeverityMedium, []string{"secret", "token", "key"}, `(?i)(?:^|[^A-Za-z0-9])["']?(?:[A-Za-z0-9]+[_-])*(?:secret|token|key)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{32,})["']?`, 3.8, redactAssignment, rem))
	add(NewRegex("openai-api-key", "OpenAI API key", "OpenAI project or service-account API key, with or without an assignment.", "ai", model.SeverityCritical, []string{"openai_api_key", "sk-proj-", "sk-svcacct-"}, `(?i)(?:^|[^A-Za-z0-9])(?:["']?(?:[A-Za-z0-9]+[_-])*openai[_-]api[_-]key["']?\s*[:=]\s*["']?)?((?:sk-(?:proj-|svcacct-))[A-Za-z0-9_\-]{20,})(?:["']|$)`, 3.2, redactAssignment, rem))
	add(NewRegex("supabase-secret-key", "Supabase secret key", "Supabase server-side secret key; publishable keys are excluded.", "cloud", model.SeverityCritical, []string{"sb_secret_"}, `\bsb_secret_[A-Za-z0-9_\-]{20,}\b`, 3.2, tokenRedactor, rem))
	add(NewRegex("anthropic-api-key", "Anthropic API key", "Anthropic API key with its provider prefix.", "ai", model.SeverityCritical, []string{"anthropic_api_key", "sk-ant-"}, `\bsk-ant-[A-Za-z0-9_\-]{40,}\b`, 3.2, tokenRedactor, rem))
	add(NewRegex("digitalocean-token", "DigitalOcean access token", "DigitalOcean personal, OAuth access, or OAuth refresh token.", "cloud", model.SeverityCritical, []string{"dop_v1_", "doo_v1_", "dor_v1_"}, `\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b`, 3.2, tokenRedactor, rem))
	add(NewRegex("huggingface-token", "Hugging Face token", "Hugging Face user access or short-lived token-exchange credential.", "ai", model.SeverityCritical, []string{"hf_", "hf_jwt_", "hf_oauth_"}, `\bhf_(?:[A-Za-z]{34}|(?:jwt|oauth)_[A-Za-z0-9._\-]{20,1000})\b`, 3.0, tokenRedactor, rem))
	add(NewRegex("hcp-terraform-token", "HCP Terraform API token", "HCP Terraform user, team, or organization API token.", "infrastructure", model.SeverityCritical, []string{"atlasv1"}, `(?:^|[^A-Za-z0-9_])([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-=]{60,70})(?:[^A-Za-z0-9_\-=]|$)`, 3.5, tokenRedactor, rem))
	add(NewRegex("hashicorp-vault-token", "HashiCorp Vault token", "Vault service, batch, or recovery token.", "secrets-manager", model.SeverityCritical, []string{"hvs.", "hvb.", "hvr."}, `(?:^|[^A-Za-z0-9_])((?:hvs|hvb|hvr)\.[A-Za-z0-9_\-]{24,})(?:[^A-Za-z0-9_\-]|$)`, 3.2, tokenRedactor, rem))
	add(NewRegex("azure-storage-account-key", "Azure Storage account key", "Azure Storage connection-string AccountKey value.", "cloud", model.SeverityCritical, []string{"AccountKey="}, `(?i)\bAccountKey=([A-Za-z0-9+/]{86}==)`, 3.5, redactAssignment, rem))
	all = append(all, custom...)
	return all
}

func GenericRemediation() []string {
	return []string{
		"Rotate or revoke the affected credential through its provider.",
		"Review provider logs for suspicious use.",
		"Replace the credential in legitimate deployments.",
		"Remove it from the current source tree.",
		"Determine whether Git history rewriting is required.",
		"Coordinate with collaborators before rewriting shared history.",
		"Protect important branches and create backups.",
		"Use an established history-rewriting tool if authorized.",
		"Force-push only after explicit team approval.",
		"Invalidate old clones, caches, artifacts, logs, and CI variables where applicable.",
		"Run RepoReaper verification.",
		"Enable preventive controls.",
	}
}

func suppress(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	if l == "" || strings.HasPrefix(l, "${") || strings.HasPrefix(l, "{{") || strings.HasPrefix(l, "your_") || strings.HasPrefix(l, "your-") {
		return true
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "", " ", "", "'", "", `"`, "").Replace(l)
	for _, word := range []string{"example", "sample", "placeholder", "changeme", "dummy", "notasecret", "fake"} {
		remainder := strings.ReplaceAll(compact, word, "")
		remainder = strings.Trim(remainder, "0123456789")
		if remainder == "" && strings.Contains(compact, word) {
			return true
		}
	}
	if len(compact) >= 5 {
		allMask := true
		for _, r := range compact {
			if r != 'x' && r != '*' && r != '0' {
				allMask = false
				break
			}
		}
		if allMask {
			return true
		}
	}
	return false
}

func looksLikeDetectorSource(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, `[\s\s]`) || (strings.Contains(l, `\s`) && strings.ContainsAny(l, `[]*?`))
}

func validateJWT(_, secret string) bool {
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return false
	}
	decode := func(part string) ([]byte, error) {
		if decoded, err := base64.RawURLEncoding.DecodeString(part); err == nil {
			return decoded, nil
		}
		return base64.URLEncoding.DecodeString(part)
	}
	headerBytes, err := decode(parts[0])
	if err != nil {
		return false
	}
	claimsBytes, err := decode(parts[1])
	if err != nil {
		return false
	}
	signature, err := decode(parts[2])
	if err != nil || len(signature) < 8 {
		return false
	}
	var header map[string]any
	var claims map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(claimsBytes, &claims) != nil || len(claims) == 0 {
		return false
	}
	algorithm, ok := header["alg"].(string)
	return ok && algorithm != "" && !strings.EqualFold(algorithm, "none")
}

func validateDockerAuth(_, secret string) bool {
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(secret)
	}
	if err != nil || len(decoded) > 4096 {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	return ok && username != "" && len(password) >= 8 && !suppress(password)
}

func validateJSONPrivateKey(_, secret string) bool {
	decoded, err := strconv.Unquote(`"` + secret + `"`)
	if err != nil {
		return false
	}
	return strings.Contains(decoded, "-----BEGIN PRIVATE KEY-----") && strings.Contains(decoded, "-----END PRIVATE KEY-----")
}

func validatePEMPrivateKey(matched, _ string) bool {
	block, rest := pem.Decode([]byte(matched))
	if block == nil || len(block.Bytes) == 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return false
	}
	switch block.Type {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK":
		return true
	default:
		return false
	}
}

func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	var e float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

func lineNumber(s string, idx int) int { return strings.Count(s[:idx], "\n") + 1 }
func tokenRedactor(s string) string {
	runes := []rune(s)
	if len(runes) <= 16 {
		return strings.Repeat("*", len(runes))
	}
	return string(runes[:4]) + strings.Repeat("*", len(runes)-8) + string(runes[len(runes)-4:])
}
func redactBearer(s string) string {
	parts := strings.Fields(s)
	if len(parts) == 2 {
		return parts[0] + " " + tokenRedactor(parts[1])
	}
	return tokenRedactor(s)
}
func redactAssignment(s string) string {
	i := strings.IndexAny(s, "=:")
	if i < 0 {
		return tokenRedactor(s)
	}
	return s[:i+1] + " [REDACTED]"
}
func redactURLPassword(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return tokenRedactor(s)
	}
	name := u.User.Username()
	u.User = url.UserPassword(name, "********")
	return u.String()
}
