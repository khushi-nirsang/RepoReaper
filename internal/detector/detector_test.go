package detector

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/khushi/reporeaper/internal/config"
	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
)

func TestBuiltInDetectorRedactsAndFingerprints(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A1b2C3d4E5f6G7h8I9j0K1l2M3n4", 2)
	ds := Registry(nil, nil)
	var got Match
	for _, d := range ds {
		if d.ID() == "github-token" {
			ms := d.Find([]byte("GITHUB_TOKEN=" + secret))
			if len(ms) != 1 {
				t.Fatalf("matches = %d", len(ms))
			}
			got = ms[0]
		}
	}
	if got.Fingerprint == "" || len(got.Short) != 12 {
		t.Fatalf("missing fingerprint: %+v", got)
	}
	if strings.Contains(got.Redacted, secret) || !strings.Contains(got.Redacted, "***") {
		t.Fatalf("unsafe redaction: %q", got.Redacted)
	}
}

func TestSanitizeMatchesScrubsCrossMatchMetadataAndCachedEvidence(t *testing.T) {
	firstValue := "ghp_" + strings.Repeat("Synth3ticCaptureAlpha1234567890", 1)
	secondValue := "ghp_" + strings.Repeat("Synth3ticCaptureBravo1234567890", 1)
	firstFull, firstShort := fingerprint.SHA256(firstValue)
	secondFull, secondShort := fingerprint.SHA256(secondValue)
	matches := []Match{
		{
			DetectorID: "github-token", Value: firstValue,
			Fingerprint: firstFull, Short: firstShort, Confidence: model.ConfidenceHigh,
			Redacted: "related=" + secondValue, Location: "archive/" + firstValue, Decoder: "zip",
		},
		{
			DetectorID: "github-token", Value: secondValue,
			Fingerprint: secondFull, Short: secondShort, Confidence: model.ConfidenceHigh,
			Redacted: "ghp_******7890", Location: "ordinary.env", Decoder: "zip",
		},
	}

	sanitized, scrubber, valid := SanitizeMatches(matches)
	if !valid {
		t.Fatal("valid synthetic matches were rejected")
	}
	for _, match := range sanitized {
		if match.ValueLength != len(match.Value) {
			t.Fatalf("value length = %d, want %d", match.ValueLength, len(match.Value))
		}
		for _, metadata := range []string{match.Redacted, match.Location, match.Decoder} {
			if scrubber.Contains(metadata) || strings.Contains(metadata, firstValue) || strings.Contains(metadata, secondValue) {
				t.Fatalf("captured value remained in sanitized metadata %q", metadata)
			}
		}
	}

	cached := append([]Match(nil), sanitized...)
	for index := range cached {
		cached[index].Value = ""
	}
	cachedScrubber, valid := NewCaptureScrubber(cached)
	if !valid {
		t.Fatal("fingerprint-and-length cache metadata was not self-validating")
	}
	evidence := "refs/heads/" + firstValue + "/fixture"
	scrubbed := cachedScrubber.Scrub(evidence)
	if scrubbed == evidence || strings.Contains(scrubbed, firstValue) || cachedScrubber.Contains(scrubbed) {
		t.Fatalf("cached scrubber did not remove captured evidence: %q", scrubbed)
	}
}

func TestPlaceholderSuppression(t *testing.T) {
	ds := Registry(nil, nil)
	for _, d := range ds {
		if d.ID() == "generic-api-key" {
			if ms := d.Find([]byte(`api_key="placeholderplaceholderplaceholder123"`)); len(ms) != 0 {
				t.Fatalf("placeholder matched: %+v", ms)
			}
		}
	}
}

func TestDetectorSourcePatternSuppression(t *testing.T) {
	content := []byte("pattern := `-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]*?-----END OPENSSH PRIVATE KEY-----`")
	for _, d := range Registry(nil, nil) {
		if d.ID() == "openssh-private-key" && len(d.Find(content)) != 0 {
			t.Fatal("detector implementation regex was reported as a private key")
		}
	}
}

func TestRequiredDetectorIDsRegistered(t *testing.T) {
	want := []string{"aws-access-key-id", "aws-secret-access-key", "github-token", "gitlab-token", "slack-token", "google-api-key", "stripe-key", "twilio-credential", "sendgrid-api-key", "npm-token", "pypi-token", "jwt", "generic-bearer-token", "generic-api-key", "postgres-connection-string", "mysql-connection-string", "mongodb-connection-string", "redis-credential-url", "basic-auth-url", "pem-private-key", "openssh-private-key", "pgp-private-key", "kubernetes-secret", "docker-registry-credential", "env-password", "service-account-json", "high-entropy-secret", "openai-api-key", "anthropic-api-key", "digitalocean-token", "huggingface-token", "hcp-terraform-token", "hashicorp-vault-token", "azure-storage-account-key"}
	got := map[string]bool{}
	for _, d := range Registry(nil, nil) {
		got[d.ID()] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("detector %s not registered", id)
		}
	}
}

func TestConfiguredBuiltInIDsMatchRegistry(t *testing.T) {
	configured := map[string]bool{}
	for _, id := range config.BuiltInDetectorIDs() {
		configured[id] = true
	}
	registered := map[string]bool{}
	for _, d := range Registry(nil, nil) {
		registered[d.ID()] = true
	}
	if len(configured) != len(registered) {
		t.Fatalf("configured IDs = %d, registered detectors = %d", len(configured), len(registered))
	}
	for id := range configured {
		if !registered[id] {
			t.Errorf("configured detector %s is not registered", id)
		}
	}
	for id := range registered {
		if !configured[id] {
			t.Errorf("registered detector %s is absent from config validation", id)
		}
	}
}

func TestScanSignatureBindsSharedAndContentSemantics(t *testing.T) {
	base := ScanSignature("rule-v1", "content-v1")
	if base == ScanSignature("rule-v1", "content-v2") || base == ScanSignature("rule-v2", "content-v1") {
		t.Fatal("scan signature ignored shared or content semantics")
	}
	if len(base) != 64 {
		t.Fatalf("scan signature length = %d", len(base))
	}
}

func TestFingerprintUsesCapturedSecretNotAssignment(t *testing.T) {
	d, err := NewRegex("custom", "Custom", "Custom detector", "custom", model.SeverityHigh, []string{"token"}, `token=([A-Za-z0-9]{24,})`, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := "Ab3dE5fG7hJ9kLmN2pQr4sTu"
	a := d.Find([]byte("token=" + secret))
	b := d.Find([]byte("prefix token=" + secret))
	if len(a) != 1 || len(b) != 1 || a[0].Fingerprint != b[0].Fingerprint {
		t.Fatalf("captured-secret fingerprint was not stable: %#v %#v", a, b)
	}
	if a[0].Value != secret {
		t.Fatalf("fingerprinted value = %q", a[0].Value)
	}
}

func TestShortCustomMatchIsFullyMasked(t *testing.T) {
	d, err := NewRegex("short", "Short", "Short custom value", "custom", model.SeverityLow, nil, `ABC1`, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	matches := d.Find([]byte("ABC1"))
	if len(matches) != 1 || strings.Contains(matches[0].Redacted, "ABC1") {
		t.Fatalf("short secret was not safely redacted: %#v", matches)
	}
}

func TestDatabasePasswordRedactionAndFingerprinting(t *testing.T) {
	content := []byte("DATABASE_URL=postgres://app:V7r9Q2m4L8x6N3p5@db.invalid/app")
	for _, d := range Registry(nil, nil) {
		if d.ID() != "postgres-connection-string" {
			continue
		}
		matches := d.Find(content)
		if len(matches) != 1 {
			t.Fatalf("matches = %d", len(matches))
		}
		if matches[0].Value != "V7r9Q2m4L8x6N3p5" || strings.Contains(matches[0].Redacted, matches[0].Value) {
			t.Fatalf("unsafe or incorrect database match: %#v", matches[0])
		}
		return
	}
	t.Fatal("postgres detector not registered")
}

func TestEntropy(t *testing.T) {
	if Entropy("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") >= Entropy("Ab3xY9LmN2pQ8rT7vW6zK5jH4gF") {
		t.Fatal("entropy ordering was not useful")
	}
}

func TestStructuredValidatorsRejectMalformedCandidates(t *testing.T) {
	tests := map[string]string{
		"jwt":                        "eyJub3QiOiJoZWFkZXIifQ.eyJub3QiOiJjbGFpbXMifQ.not-a-real-signature",
		"docker-registry-credential": `{"auths":{"registry.invalid":{"auth":"QUFBQUFBQUFBQUFBQUFBQUFB"}}}`,
		"service-account-json":       `{"type":"service_account","private_key":"this-is-not-a-private-key-value"}`,
	}
	for _, d := range Registry(nil, nil) {
		content, ok := tests[d.ID()]
		if ok && len(d.Find([]byte(content))) != 0 {
			t.Fatalf("%s accepted malformed structured input", d.ID())
		}
	}
}

func TestStructuredValidatorsAcceptValidShapes(t *testing.T) {
	assertDetectorMatch(t, "jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvcmVhcGVyLXRlc3QifQ.MDEyMzQ1Njc4OWFiY2RlZg")
	auth := base64.StdEncoding.EncodeToString([]byte("repo-reaper:" + strings.Repeat("Q7mK9pR2vL4xN6dF8hJ3sT5w", 1)))
	assertDetectorMatch(t, "docker-registry-credential", `{"auths":{"registry.invalid":{"auth":"`+auth+`"}}}`)
	assertDetectorMatch(t, "service-account-json", `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nUjNwb1JlYXBlclRlc3RLZXk=\n-----END PRIVATE KEY-----\n"}`)
}

func TestProviderDetectorPrecision(t *testing.T) {
	synthetic := func(prefix string, length int) string {
		alphabet := "Ab3dE5fG7hJ9kLmN2pQr4sTuVwXyZaBc"
		return prefix + strings.Repeat(alphabet, (length/len(alphabet))+1)[:length]
	}
	hex := func(prefix string, length int) string {
		alphabet := "0123456789abcdef"
		return prefix + strings.Repeat(alphabet, (length/len(alphabet))+1)[:length]
	}
	keyBytes := make([]byte, 64)
	for i := range keyBytes {
		keyBytes[i] = byte(i*37 + 11)
	}
	fixtures := map[string]string{
		"aws-secret-access-key":     "AWS_SECRET_ACCESS_KEY=" + strings.Repeat("Q7mK9pR2vL4xN6dF8hJ3sT5wY1zA0bC2eG4iU6oP", 1),
		"openai-api-key":            "OPENAI_API_KEY=" + synthetic("sk-proj-", 32),
		"anthropic-api-key":         synthetic("sk-ant-", 48),
		"digitalocean-token":        hex("dop_v1_", 64),
		"huggingface-token":         "hf_" + strings.Repeat("AbCdEfGhIjKlMnOpQrStUvWxYz", 2)[:34],
		"hcp-terraform-token":       synthetic("Ab3dE5fG7hJ9kL", 0) + ".atlasv1." + synthetic("", 65),
		"hashicorp-vault-token":     synthetic("hvs.", 32),
		"azure-storage-account-key": "AccountKey=" + base64.StdEncoding.EncodeToString(keyBytes),
	}
	for detectorID, content := range fixtures {
		t.Run(detectorID, func(t *testing.T) { assertDetectorMatch(t, detectorID, content) })
	}
}

func TestModernProviderTokenVariants(t *testing.T) {
	fixtures := map[string][]string{
		"gitlab-token": {
			"glcbt-" + strings.Repeat("A1b2C3d4E5f6G7h8", 2),
			"glwt-" + strings.Repeat("B2c3D4e5F6g7H8i9", 2),
		},
		"slack-token": {
			"xapp-" + strings.Repeat("A1b2C3d4E5f6G7h8", 3),
			"xwfp-" + strings.Repeat("C3d4E5f6G7h8I9j0", 2),
			"xoxe-" + strings.Repeat("D4e5F6g7H8i9J0k1", 2),
		},
		"digitalocean-token": {
			"doo_v1_" + strings.Repeat("fedcba9876543210", 4),
			"dor_v1_" + strings.Repeat("13579bdf02468ace", 4),
		},
		"huggingface-token": {
			"hf_jwt_" + strings.Repeat("A1b2C3d4E5f6G7h8", 3),
			"hf_oauth_" + strings.Repeat("B2c3D4e5F6g7H8i9", 2),
		},
	}
	for detectorID, values := range fixtures {
		for _, value := range values {
			assertDetectorMatch(t, detectorID, value)
		}
	}
}

func TestModernProviderDetectorsRejectWeakOrMalformedCandidates(t *testing.T) {
	fixtures := map[string][]string{
		"digitalocean-token": {
			"dop_v1_0123456789abcdef",
			"dop_v1_0000000000000000000000000000000000000000000000000000000000000000",
		},
		"huggingface-token": {
			"hf_short",
			"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
		"hcp-terraform-token": {
			"short.atlasv1.Q7mK9pR2vL4xN6dF8hJ3sT5wY1zA0bC2eG4iU6oP8qR7tV9xB3nM5kL2",
			"xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		},
	}
	for _, d := range Registry(nil, nil) {
		for _, value := range fixtures[d.ID()] {
			if matches := d.Find([]byte(value)); len(matches) != 0 {
				t.Fatalf("%s accepted malformed or weak candidate %q", d.ID(), value)
			}
		}
	}
}

func TestAssignmentDetectorsHandleQuotedQualifiedAndHyphenatedKeys(t *testing.T) {
	fixtures := map[string]string{
		"generic-api-key": `{"OIDC_CLIENT_SECRET":"Ab3dE5fG7hJ9kLmN2pQr4sTuVwXyZaBc"}`,
		"env-password":    `DB_PASSWORD="` + strings.Repeat("Q7mK9pR2vL4xN6dF8hJ3sT5w", 1) + `"`,
		"openai-api-key":  `{"openai_api_key":"` + "sk-proj-" + strings.Repeat("Q7mK9pR2vL4xN6dF8hJ3sT5wY1zA", 1) + `"}`,
	}
	for detectorID, fixture := range fixtures {
		assertDetectorMatch(t, detectorID, fixture)
	}
	for _, detector := range Registry(nil, nil) {
		if detector.ID() == "generic-api-key" && len(detector.Find([]byte("monkey=Ab3dE5fG7hJ9kLmN2pQr4sTuVwXyZa"))) != 0 {
			t.Fatal("generic API key matched an unrelated identifier")
		}
	}
}

func TestProviderCredentialDistinguishesTwilioIdentifiers(t *testing.T) {
	for _, detector := range Registry(nil, nil) {
		switch detector.ID() {
		case "twilio-credential":
			matches := detector.Find([]byte("AC" + strings.Repeat("0123456789abcdef", 2)))
			if len(matches) != 1 || detector.Severity() != model.SeverityInfo {
				t.Fatalf("Twilio SID classification = %d %#v", len(matches), detector.Severity())
			}
		case "twilio-auth-token":
			assertDetectorMatch(t, detector.ID(), "TWILIO_AUTH_TOKEN="+strings.Repeat("0123456789abcdef", 2))
		}
	}
}

func TestPEMDetectorsRejectMalformedOrMismatchedArmor(t *testing.T) {
	for _, detector := range Registry(nil, nil) {
		if detector.ID() != "pem-private-key" {
			continue
		}
		for _, fixture := range []string{
			"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----",
		} {
			if len(detector.Find([]byte(fixture))) != 0 {
				t.Fatalf("malformed PEM was accepted: %q", fixture)
			}
		}
		return
	}
	t.Fatal("PEM detector not registered")
}

func TestKubernetesDetectorIsSchemaScopedAndDecodesSecretData(t *testing.T) {
	secret := "ghp_" + strings.Repeat("KubernetesFake7Qm2Wv9Rk4Np8Xs3Ld6Tf", 1)
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	fixture := "kind: ConfigMap\ndata:\n  token: ordinary-value\n---\nkind: Secret\ndata:\n  credentials: " + encoded + "\nstringData:\n  database-url: " + secret + "\n"
	for _, detector := range Registry(nil, nil) {
		if detector.ID() != "kubernetes-secret" {
			continue
		}
		matches := detector.Find([]byte(fixture))
		if len(matches) != 2 {
			t.Fatalf("Kubernetes matches = %#v", matches)
		}
		for _, match := range matches {
			if match.Value != secret || !strings.HasPrefix(match.Location, "yaml:") || match.Decoder != "kubernetes-secret" {
				t.Fatalf("Kubernetes match provenance = %#v", match)
			}
		}
		return
	}
	t.Fatal("Kubernetes detector not registered")
}

func TestPlaceholderWordInsideRandomCredentialDoesNotEvadeDetection(t *testing.T) {
	assertDetectorMatch(t, "generic-api-key", "api_key=Ab3xsampleY9LmN2pQ8rT7vW6zK5jH4gF")
}

func assertDetectorMatch(t *testing.T, detectorID, content string) {
	t.Helper()
	for _, d := range Registry(nil, nil) {
		if d.ID() != detectorID {
			continue
		}
		matches := d.Find([]byte(content))
		if len(matches) != 1 {
			t.Fatalf("%s matches = %d", detectorID, len(matches))
		}
		if strings.Contains(matches[0].Redacted, matches[0].Value) {
			t.Fatalf("%s returned unsafe redaction", detectorID)
		}
		return
	}
	t.Fatalf("detector %s not registered", detectorID)
}
