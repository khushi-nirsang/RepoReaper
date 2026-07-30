package detector

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/khushi/reporeaper/internal/fingerprint"
	"github.com/khushi/reporeaper/internal/model"
	"gopkg.in/yaml.v3"
)

// kubernetesSecretDetector understands the Kubernetes Secret schema instead
// of treating every YAML token/password field as a credential. It deliberately
// stays offline and bounded: aliases are not expanded and only a finite number
// of documents/fields are visited.
type kubernetesSecretDetector struct {
	remediation []string
}

func NewKubernetesSecretDetector(remediation []string) Detector {
	return &kubernetesSecretDetector{remediation: append([]string{}, remediation...)}
}

func (d *kubernetesSecretDetector) ID() string   { return "kubernetes-secret" }
func (d *kubernetesSecretDetector) Name() string { return "Kubernetes Secret value" }
func (d *kubernetesSecretDetector) Description() string {
	return "Scalar values under data or stringData in Kubernetes Secret manifests."
}
func (d *kubernetesSecretDetector) Severity() model.Severity { return model.SeverityHigh }
func (d *kubernetesSecretDetector) Keywords() []string {
	return []string{"kind", "Secret", "data", "stringData"}
}
func (d *kubernetesSecretDetector) Category() string { return "kubernetes" }
func (d *kubernetesSecretDetector) Remediation() []string {
	return append([]string{}, d.remediation...)
}
func (d *kubernetesSecretDetector) Signature() string {
	return "kubernetes-secret-yaml-v1"
}

func (d *kubernetesSecretDetector) Find(content []byte) []Match {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var matches []Match
	for document := 0; document < 32; document++ {
		var root yaml.Node
		err := decoder.Decode(&root)
		if err != nil {
			break
		}
		mapping := rootNodeMapping(&root)
		if mapping == nil || scalarMappingValue(mapping, "kind") == nil || scalarMappingValue(mapping, "kind").Value != "Secret" {
			continue
		}
		for _, field := range []string{"data", "stringData"} {
			values := scalarMappingValue(mapping, field)
			if values == nil || values.Kind != yaml.MappingNode {
				continue
			}
			for index := 0; index+1 < len(values.Content) && index < 8192; index += 2 {
				key, value := values.Content[index], values.Content[index+1]
				if key.Kind != yaml.ScalarNode || value.Kind != yaml.ScalarNode || value.Tag == "!!null" {
					continue
				}
				candidate := value.Value
				if field == "data" {
					decoded, decodeErr := base64.StdEncoding.DecodeString(candidate)
					if decodeErr != nil {
						decoded, decodeErr = base64.RawStdEncoding.DecodeString(candidate)
					}
					if decodeErr != nil {
						continue
					}
					candidate = string(decoded)
				}
				if len(candidate) < 16 || suppress(candidate) || Entropy(candidate) < 3.0 || strings.IndexByte(candidate, 0) >= 0 {
					continue
				}
				full, short := fingerprint.SHA256(candidate)
				matches = append(matches, Match{
					DetectorID: d.ID(), Value: candidate, ValueLength: len(candidate),
					Redacted: key.Value + "=[REDACTED]", Fingerprint: full, Short: short,
					Line: value.Line, Confidence: model.ConfidenceHigh,
					Location: "yaml:" + field + "." + key.Value, Decoder: "kubernetes-secret",
				})
			}
		}
	}
	return matches
}

func rootNodeMapping(root *yaml.Node) *yaml.Node {
	if root == nil {
		return nil
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

func scalarMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Kind == yaml.ScalarNode && mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}
