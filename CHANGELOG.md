# Changelog

## Unreleased

### Added

- Bounded persistent Git batch readers, cached raw tree walking, and cached ref-containment queries.
- Opt-in bounded persistent Git-blob result cache with semantic invalidation, sanitized result/fingerprint metadata without raw blob or match content, a dedicated symlink-checked Git-directory subtree, and corruption/concurrency safeguards.
- Graph-aware concurrent exposure intervals with removal/reintroduction handling and non-overlapping duration accounting.
- Explicit tracked/untracked working-tree provenance and broad scope-aware remediation verification.
- ZIP, gzip, tar, and Base64 inspection for repository and staged scans with bounded in-memory expansion and fail-closed staged coverage.
- Detector definition signatures and offline structural validation for JWT, Docker auth, and service-account private keys.
- AWS secret assignment, OpenAI, Anthropic, DigitalOcean, Hugging Face, HCP Terraform, HashiCorp Vault, and Azure Storage detector rules.
- CI `--fail-on` severity thresholds and `--fail-scope` evidence classes.
- Safe `scan --baseline` suppression for unchanged detector/fingerprint/path/scope findings in CI.
- Bare/unborn repository support, `doctor` diagnostics, and shell completion generation.
- Report schema 1.1 with scan/verification document-type discrimination, structurally validated legacy 1.0 baseline loading, and explicit skipped-object statistics.
- DigitalOcean, Hugging Face, and HCP Terraform detectors plus expanded modern GitLab and Slack token families.
- Detector/report fuzz targets and batch/tree benchmarks.
- Cross-platform, race, fuzz, vulnerability, CodeQL, dependency-review, SBOM, and release-attestation automation with immutable commit pins for third-party actions.
- Cross-field and final report-wide capture scrubbing for repository, configuration, finding, evidence, remediation, warning, notice, and cache-hit metadata without persisting captured values.

### Changed

- Verification now builds a conservative superset scan, checks detector-rule identity, includes non-ignored untracked/residual evidence, bypasses persistent cache state, and returns incomplete instead of passing when scope cannot support absence.
- Oversized/unreadable objects, working-tree symlinks, and failed ref-containment checks now produce coverage warnings instead of silently disappearing.
- Staged protection applies configuration allowlists and blocks only high-confidence high/critical findings.
- Date-only scan bounds cover the complete local calendar day.
- Table, HTML, JSON, and SARIF reports include embedded decoder provenance and expanded performance statistics.
- Scan summaries separate configuration-allowlist and CI-baseline suppression counts while retaining the combined total.
- Policy gates evaluate all unsuppressed findings independently of presentation-only severity filters.
- Remediation verification rejects malformed fingerprints and clear cross-repository baseline mismatches.
- Detached HEAD commits are always included, and Git/ref/reflog/worktree enumeration errors can no longer disappear silently.
- Release archives use deterministic metadata where supported and include source/docs, checksums, and SPDX JSON SBOMs.

### Fixed

- Empty/unborn repository scans no longer fail while resolving HEAD.
- Oversized/missing Git objects no longer desynchronize batch reads.
- Exposure duration no longer double-counts overlapping branch intervals.

## 0.1.0

- Initial RepoReaper implementation with CLI scanning, reports, investigation, verification, staged protection, detectors, docs, tests, and release metadata.
