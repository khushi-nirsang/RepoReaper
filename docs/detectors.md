# Detector Reference

RepoReaper's detectors generate candidates with Go regular expressions and case-insensitive keyword prefilters, then apply entropy, placeholder, and format checks where configured. Every accepted match is redacted and fingerprinted with SHA-256. No detector sends a value over the network or attempts to authenticate with a provider.

Use the active configuration to inspect the installed registry:

```sh
reporeaper detectors list
reporeaper detectors describe github-token
reporeaper scan . --detector github-token,aws-secret-access-key
```

`private-key` is a CLI selection alias that expands to `pem-private-key`, `openssh-private-key`, and `pgp-private-key`; it is not itself a detector ID.

## Built-In Detectors

| Detector ID | Severity | Candidate and validation boundary |
| --- | --- | --- |
| `aws-access-key-id` | high | AWS access-key identifier prefixes and fixed-width uppercase identifier shape |
| `aws-secret-access-key` | critical | 40-character value in an explicit AWS secret-key assignment |
| `github-token` | critical | Classic, OAuth, user, server, refresh, or fine-grained GitHub token prefixes |
| `gitlab-token` | critical | Current documented GitLab token prefixes, including access, OAuth, deploy, runner, job, trigger, feed, agent, workspace, SCIM, and feature-flag tokens |
| `slack-token` | critical | Slack `xox*`, app-level, workflow, rotating tokens, or services/workflows/triggers webhook URLs |
| `google-api-key` | high | `AIza` API-key shape |
| `stripe-key` | critical | Stripe live/test secret, restricted, or webhook-signing key shape |
| `twilio-credential` | info | Twilio account-SID identifier shape; not an authentication secret by itself |
| `twilio-auth-token` | critical | Twilio Auth Token or API-key secret in an explicit assignment |
| `sendgrid-api-key` | critical | Three-part `SG.` API-key shape |
| `npm-token` | critical | `npm_` access-token shape |
| `pypi-token` | critical | `pypi-` API-token shape |
| `jwt` | medium | Three Base64URL parts; header and claims must decode as JSON, `alg` cannot be `none`, and the signature must decode to at least eight bytes |
| `generic-bearer-token` | high | High-entropy token after an explicit `Bearer` context |
| `generic-api-key` | medium | High-entropy value assigned to API-key, access-token, or client-secret keywords |
| `postgres-connection-string` | high | PostgreSQL URI containing user/password authority |
| `mysql-connection-string` | high | MySQL URI containing user/password authority |
| `mongodb-connection-string` | high | MongoDB or MongoDB SRV URI containing user/password authority |
| `redis-credential-url` | high | Redis URI containing credential authority |
| `basic-auth-url` | high | HTTP(S) URL containing username and password |
| `pem-private-key` | critical | PEM RSA, EC, DSA, encrypted, or generic private-key block with matching decodable armor |
| `openssh-private-key` | critical | OpenSSH private-key block |
| `pgp-private-key` | critical | PGP private-key block |
| `kubernetes-secret` | high | High-entropy scalar under `data` or `stringData` in a schema-scoped Kubernetes `kind: Secret` document; `data` values are Base64-decoded |
| `docker-registry-credential` | high | JSON `auth` value that Base64-decodes to a non-empty username and a non-placeholder password of at least eight characters |
| `env-password` | high | Password/passwd/pwd environment-style assignment |
| `service-account-json` | critical | JSON `private_key` string that unescapes to a complete PEM private-key boundary |
| `high-entropy-secret` | medium | High-entropy value assigned to a generic secret/token/key keyword |
| `openai-api-key` | critical | OpenAI project or service-account key shape with or without an assignment; legacy unscoped `sk-` values remain contextual |
| `anthropic-api-key` | critical | `sk-ant-` provider-prefixed key shape |
| `digitalocean-token` | critical | Fixed-width `dop_v1_`, `doo_v1_`, or `dor_v1_` personal/OAuth token shape |
| `huggingface-token` | critical | Fixed-width `hf_` user token or `hf_jwt_`/`hf_oauth_` short-lived token-exchange shape |
| `hcp-terraform-token` | critical | HCP Terraform token with fixed-width leading segment, literal `.atlasv1.`, and bounded credential segment |
| `hashicorp-vault-token` | critical | Vault service, batch, or recovery token using `hvs.`, `hvb.`, or `hvr.` |
| `supabase-secret-key` | critical | Supabase `sb_secret_` server-side key; publishable keys are excluded |
| `azure-storage-account-key` | critical | Fixed-width Base64 `AccountKey` in an Azure Storage connection string |

The table describes implemented candidate logic, not a promise that every provider format or variant is covered. Provider formats evolve. Some broad detectors intentionally require an assignment or header context to reduce noise.

## Offline Structural Validation

JWT, Docker registry auth, and service-account private-key candidates receive additional offline parsing. This rejects malformed values without transmitting them. Other built-ins are regex/context/entropy based today; in particular, Kubernetes YAML and connection URI detectors are not full schema-aware parsers.

Regex matches use high detection confidence after their configured checks pass; this does not establish provider validity or live status. Timeline confidence can later be reduced to `medium` when merge topology prevents exact introduction/removal attribution. `confirmed` does not mean provider validity and is not currently produced by built-in online validation.

## Placeholder And Entropy Handling

RepoReaper suppresses obvious template syntax, wholly masked values, and values made entirely from words such as `example`, `placeholder`, `changeme`, `dummy`, or `fake` plus separators/digits. It does not suppress a random-looking credential merely because that sequence happens to contain one of those words.

Entropy thresholds are detector-specific. Entropy is only one heuristic: high entropy does not establish validity, and low-entropy real credentials may evade entropy-gated rules.

## Embedded Content

Archive and Base64 expansion occurs before the detector registry runs. The same active detectors therefore inspect supported decoded text during repository scans. Decoder chains and logical archive-member paths are attached to evidence.

`reporeaper protect staged` applies the same supported bounded expansion to staged blob objects and records decoded location/decoder provenance. It prints non-secret coverage warnings and fails closed when an object or embedded payload cannot be fully inspected.

## Custom Detectors

Define organization-specific rules in `.reporeaper.yaml`:

```yaml
version: 1
scan:
  max_file_size: 5242880
  branches: true
  tags: true
  workers: 4
report:
  default_format: table
  redact: true
policy:
  scope: any
detectors:
  disabled:
    - high-entropy-secret
  custom:
    - id: widget-token
      name: Widget token
      description: Organization-specific Widget credential
      regex: 'WIDGET_([A-Z0-9]{24})'
      severity: high
      remediation: Rotate the Widget credential and review its audit log.
      keywords: ["WIDGET_"]
      minimum_entropy: 2.5
```

Custom regexes use Go's RE2-style syntax. If capture group 1 participates, that group is treated as the secret value for entropy and fingerprinting; otherwise the whole match is used. Keyword prefilters are case-insensitive. Custom rules receive the same placeholder suppression, redaction, and no-network behavior as built-ins, but cannot currently register a custom structural parser.

Validate the file before use:

```sh
reporeaper config validate --config .reporeaper.yaml
```

Disabling a detector removes it from ordinary scans and staged protection. Verification re-enables built-ins so a local disabled list cannot hide baseline evidence, but a baseline custom detector must still exist in the active configuration.

## Rule Signatures And Verification

JSON scan configuration records a SHA-256 signature for every active detector. For regex detectors, the signature covers detector ID, expression, entropy threshold, keyword list, and structural-validator version identifier. Verification requires the baseline and current signature to match before absence can be considered reproducible.

A signature does not prove provider validity and is not a general plugin authenticity signature. Older reports without signatures and reports made with changed detector definitions produce incomplete verification for affected findings.

## Detection Limits

- RepoReaper does not contact provider APIs or confirm whether a key is active, revoked, expired, scoped, or test-only.
- Regex and entropy detection produces both false positives and false negatives.
- The current built-in registry is focused rather than exhaustive; it does not match the provider-rule breadth of every mature commercial scanner.
- Unsupported binary, encrypted, or deeply nested payloads are not decoded.
- A new provider token format requires a detector update before it can be recognized specifically.
- Custom regex mistakes can miss values or create excessive matches; test them only with synthetic fixtures.
