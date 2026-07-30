# RepoReaper

RepoReaper is a local-first defensive Git forensics tool for investigating whether credentials remain recoverable after they were deleted from the latest source tree.

**Deleting a secret from the latest commit does not revoke it and does not necessarily remove it from Git history. Rotate or revoke exposed credentials first.**

## Features

- Scans the Git index, tracked working-tree files, optional non-ignored untracked files, branch/tag history, all refs, reflogs, and unreachable objects.
- Inspects UTF-8 and UTF-16 text, plus text embedded in ZIP, gzip, and tar payloads and Base64-encoded text, with bounded in-memory expansion and archive-bomb guards.
- Detects common token, key, connection-string, private-key, package-registry, cloud, AI-provider, Kubernetes Secret, Docker, Vault, Supabase, and high-entropy patterns.
- Uses offline structural validation for JWTs, Docker registry auth, and cloud service-account private keys where a regex alone is too permissive.
- Redacts all findings and applies a final report-wide scrub for captured values across repository, configuration, finding, evidence, remediation, warning, and notice metadata while preserving deterministic SHA-256 proof values.
- Builds graph-aware exposure timelines with separate introduction, removal, reintroduction, and still-open branch intervals where Git history allows it.
- Separates current HEAD, index, tracked/untracked working-tree, reachable-history, tag, remote-tracking-ref, reflog, and unreachable-object evidence.
- Produces table, JSON, HTML, and SARIF reports.
- Verifies remediation against a previous JSON baseline and refuses to claim absence when scan scope, objects, or detector definitions cannot be reproduced.
- Provides optional local pre-commit protection for staged content.
- Supports severity and evidence-scope policy gates for CI.
- Can compare a CI scan to a restricted JSON baseline while keeping new paths and newly expanded exposure scopes visible.
- Uses persistent `git cat-file --batch` readers and a shared tree-object cache to avoid one Git process per blob.
- Offers an opt-in, bounded persistent Git-blob result cache that stores sanitized result/fingerprint metadata without raw blob or match content and invalidates on detector-matching, cached-result, or expansion-semantics changes.
- Provides read-only installation/repository diagnostics and generated shell completion scripts.

## Install And Build

Go 1.24 or newer is required. CI tests the minimum version from `go.mod` as well as the current project toolchain used by the release jobs.

```sh
go build -o reporeaper .
go install .
```

## Examples

```sh
reporeaper scan .
reporeaper scan . --all-refs --unreachable --reflogs
reporeaper scan . --format json --output report.json
reporeaper scan . --format html --output report.html
reporeaper scan . --cache
reporeaper scan . --fail-on high --fail-scope current
reporeaper scan . --baseline accepted.json --fail-on high --fail-scope current
reporeaper investigate --report report.json --finding RR-0001
reporeaper verify . --baseline report.json --format json --output verification.json
reporeaper detectors list
reporeaper doctor .
reporeaper completion powershell
reporeaper protect install
reporeaper protect staged
```

See the [complete operating guide](docs/guide.md) for scan scope, report interpretation, remediation verification, hook behavior, CI integration, and exit codes.

Example table output uses redacted values only:

```text
RR-0001  critical  high  github-token  ghp_1A************************3456  config.env:1  2025-01-01  history-only  possible  90
```

## Configuration

Create `.reporeaper.yaml`:

```yaml
version: 1
scan:
  max_file_size: 5242880
  include_untracked: false
  branches: true
  tags: true
  unreachable: false
  reflogs: false
  workers: 4
  cache:
    enabled: false
    path: ""
    max_entries: 50000
    max_size: 67108864
report:
  default_format: table
  redact: true
policy:
  fail_on: ""
  scope: any
allowlist:
  fingerprints: []
  paths:
    - "testdata/**"
  commits: []
  regexes: []
detectors:
  disabled: []
  custom: []
```

Validate it with:

```sh
reporeaper config validate
```

## Detector List

Built-ins include AWS access key identifiers and secret-key assignments, GitHub tokens, current GitLab token families, Slack tokens and webhooks, Google API keys, Stripe secret/restricted/webhook keys, Twilio SIDs and assigned authentication secrets, SendGrid keys, npm tokens, PyPI tokens, structurally valid JWTs, bearer tokens, generic API keys, PostgreSQL/MySQL/MongoDB/Redis credential URLs, basic-auth URLs, PEM/OpenSSH/PGP private keys, schema-scoped Kubernetes Secret values, validated Docker registry auth, environment password assignments, cloud service-account private keys, OpenAI, Anthropic, DigitalOcean, Hugging Face, HCP Terraform, HashiCorp Vault, Supabase secret keys, and Azure Storage credentials, plus high-entropy unknown secrets.

Run `reporeaper detectors list` for the active registry and see [detector reference](docs/detectors.md) for exact IDs and validation limits.

## Verification Workflow

1. Rotate or revoke the credential with its provider.
2. Remove legitimate source references.
3. Save a broad baseline: `reporeaper scan . --include-untracked --all-refs --reflogs --unreachable --format json --output baseline.json`.
4. Perform authorized history cleanup if required.
5. Re-scan and verify: `reporeaper verify . --baseline baseline.json`.

Verification automatically requests a conservative superset of the baseline scope, including non-ignored untracked files, every local ref (including direct blob/tree refs), reflogs, and unreachable objects. It deliberately bypasses the optional persistent cache so a cached negative result cannot support a remediation claim. Keep any custom detector definitions available in the active configuration. A missing or changed detector signature, a shallow clone, an unreadable object, or any scan warning makes absence verification incomplete instead of passing.

RepoReaper never confirms credential revocation because it does not contact providers. It also cannot prove deletion from a remote service or another clone.

## Safety Model

RepoReaper is read-only by default. It does not rewrite history, delete refs, expire reflogs, run garbage collection, force-push, upload repository contents, validate credentials online, send telemetry, or print full secrets. Report files are written atomically with owner-only permissions where the platform supports it. Windows ACL behavior depends on the parent directory. `--cache` is an explicit local-write opt-in; its bounded cache is kept in a dedicated, symlink-checked subtree inside the repository Git directory.

## Limitations

- RepoReaper cannot confirm whether a credential is active.
- RepoReaper cannot prove every remote copy was removed.
- Shallow or incomplete clones produce incomplete results.
- Deleted remote branches may not be represented locally.
- Git LFS content may not be available.
- Ignored untracked files are excluded by Git and must be inspected separately when relevant.
- Garbage-collected objects cannot be inspected.
- Secret detection may produce false positives and false negatives.
- Top-level files and Git blobs above `--max-file-size` are skipped with a coverage warning and counted in `objects_skipped`; increase the limit deliberately when needed.
- Embedded inspection currently supports UTF-16LE/BE, ZIP, gzip, tar, and Base64 text; it does not support every archive or encoding.
- Submodule repositories are not scanned recursively. Staged protection expands the same supported UTF-16, ZIP, gzip, tar, and Base64 payloads and fails closed if any staged content cannot be completely inspected.
- Bare repositories are supported for history/ref/object scans; they have no ordinary index, working-tree, or staged-protection scope.
- JSON scan reports contain full unsalted SHA-256 fingerprints for exact verification; table, HTML, and SARIF output expose only shortened fingerprints. Hashes are not raw secrets, but weak password fingerprints may be guessable, so every report must remain restricted.
- The optional persistent cache also contains redacted previews and full fingerprints, never raw blob bytes or raw matches. Its checksums detect accidental corruption; they do not authenticate cache authorship. Treat an enabled cache as trusted, sensitive local state and do not reuse one from an untrusted or shared Git directory.
- `--check-remote` is intentionally deferred; current remote analysis is based on local metadata and remote-tracking refs only.

## Development

```sh
gofmt -l $(git ls-files --cached --others --exclude-standard '*.go')
go vet ./...
go test -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build -trimpath ./...
```

The `gofmt -l` command must print no files and excludes ignored caches through Git's file list. In PowerShell, assign that `git ls-files` result to a variable and pass it to `gofmt -l`. Equivalent Make targets are available when `make` is installed. Run `go test -race -count=1 ./...` only where CGO and a C compiler are available. The repository CI is configured for cross-platform tests, coverage, Linux race tests, fuzz smoke tests, `govulncheck`, and a GoReleaser snapshot. CodeQL and dependency review are configured for public-repository runs. The tagged-release workflow is configured to produce SHA-256 checksums and SPDX JSON SBOMs and submit artifacts for GitHub attestation; verify a particular release's workflow result and artifacts rather than inferring publication from this configuration.

## CI Integration

The scan report is written before a policy failure is returned. This lets CI retain a restricted SARIF/JSON result while still failing the job:

```sh
reporeaper scan . --include-untracked --all-refs --format sarif --output reporeaper.sarif --fail-on high --fail-scope current
reporeaper scan . --include-untracked --format sarif --output new-findings.sarif --baseline accepted.json --fail-on high --fail-scope current
reporeaper protect staged
```

Policy scopes are `current` (HEAD, index, or working tree), `reachable` (commit/ref history), `residual` (reflog or unreachable objects), and `any`. `--fail-on` is a minimum severity threshold. The `--severity` flag filters report presentation only and cannot weaken the policy gate.

`--baseline` is for new-finding triage, not cleanup verification. A finding is treated as already known only when detector ID and full SHA-256 fingerprint match, all current normalized paths were already associated with it, and it has not expanded into HEAD, index, working-tree, tracked, untracked, reflog, or unreachable scope. New paths and newly dirty scopes remain visible and can fail policy. Use the same or broader scan scope when producing/comparing CI baselines; the flag does not scan evidence omitted by current options.

Treat reports as security metadata. Do not publish them as unrestricted build artifacts.

## Roadmap

The current priority order is documented in [improvements and roadmap](docs/improvements.md). Major future work includes optional non-secret remote metadata checks, broader structured-format validation, signed detector packs, and stronger compatibility/performance guarantees. None of those features may transmit secret values or weaken default redaction.

## License

Apache-2.0.
