# Improvements And Roadmap

This file distinguishes shipped engineering work from open product gaps. It is not a promise that RepoReaper is already superior to every mature secret scanner.

## Recently Delivered

- Persistent, bounded `git cat-file --batch` blob readers instead of one process per blob.
- Opt-in, bounded persistent Git-blob result caching with semantic invalidation, sanitized result/fingerprint metadata without raw blob or match content, corruption-safe misses, atomic writes, and a dedicated symlink-checked subtree inside the Git directory.
- Raw Git tree walking with a scan-local shared-tree cache and a safe command fallback.
- Cached ref-containment queries focused on timeline boundary commits.
- Branch-aware introduction, removal, reintroduction, and concurrent exposure intervals, with unioned duration.
- Explicit HEAD, every Git-index stage, tracked working-tree, untracked-file, reflog, and unreachable-object provenance.
- ZIP, gzip, tar, nested transformation, and Base64 text inspection with in-memory expansion limits.
- UTF-16LE/BE text decoding with bounded provenance and gzip ratio enforcement.
- Schema-scoped Kubernetes Secret parsing, modern Stripe/Supabase/OpenAI formats, and Twilio identifier/secret separation.
- Offline structural validation for JWT, Docker registry auth, and service-account private-key candidates.
- Provider rules for AWS secret-key assignments, OpenAI, Anthropic, HashiCorp Vault, and Azure Storage credentials.
- High-confidence DigitalOcean, Hugging Face, and HCP Terraform rules plus expanded modern GitLab and Slack token families.
- Detector definition signatures and scope-aware remediation verification.
- CI severity thresholds and `current`, `reachable`, `residual`, or `any` evidence gates.
- CI baseline suppression keyed by detector/full fingerprint, normalized path subsets, and non-expanding current/residual scope.
- Staged protection using bounded batch object reads plus the same ZIP, gzip, tar, and Base64 expansion as repository scans.
- Bare and unborn repository handling.
- Read-only `doctor` diagnostics and generated Bash, Zsh, Fish, and PowerShell completions.
- Detector/report fuzz targets, batch/tree/detector microbenchmarks, cross-platform tests, Linux race tests, Go vulnerability analysis, and public-repository CodeQL/dependency review.
- Reproducibility-oriented release metadata, archive/source checksums, SPDX JSON SBOMs, GitHub artifact attestations, and reviewed immutable commit pins for third-party workflow actions.

## Highest-Priority Product Gaps

1. Expand provider breadth and structured validation. Kubernetes YAML, connection URIs, cloud configuration, and many provider formats are still regex/context based, and the built-in rule count remains smaller than mature market scanners.
2. Add explicit staged-scan resource metrics and keep embedded-content hook latency predictable as format coverage grows.
3. Formalize schema migration beyond current legacy 1.0 loading, including explicit per-field compatibility guarantees.
4. Add measurable performance budgets and repeatable large synthetic repository benchmarks in CI, including memory ceilings, cancellation latency, and goroutine/process leak checks.

## Important Follow-Up

- Add optional, explicit remote metadata checks without transmitting secret values. Document every request and keep local evidence authoritative when the network is unavailable.
- Add deeper merge-parent attribution and path-sensitive explanations for mixed-presence merges; current intervals preserve concurrent paths but still mark intrinsically ambiguous merges.
- Add provider-specific remediation links and rotation checklists that never claim revocation.
- Support more archive/encoding formats only when they can be parsed safely in process; encrypted archives and external decompression should remain opt-in or unsupported.
- Improve hook interoperability. The current installer intentionally refuses to merge with or replace a foreign pre-commit hook.
- Define a signed-detector-pack/plugin model if externally supplied rules are added; current custom detectors are local YAML regexes only.
- Add package-manager installation channels and verify release attestations/SBOMs in published installation instructions.
- Add stable machine-readable output for detector inventory and diagnostics if integrations require it; current detector listing is text and `doctor` supports text/JSON.

## Known Design Limits

- RepoReaper can inspect only objects and refs available locally. It cannot inspect garbage-collected objects or prove that deleted remote refs no longer exist.
- Remote status comes only from local remote-tracking refs and sanitized remote configuration; no server is contacted.
- Git LFS objects are not fetched, and submodule repositories are not scanned recursively.
- Provider validity, revocation, expiration, use, and audit history cannot be established offline.
- Detection remains heuristic and can produce false positives and false negatives.
- Supported embedded formats are ZIP, gzip, ustar-compatible tar, and Base64 text with finite nesting/resource limits.
- Staged protection fails closed on coverage warnings; legitimate large staged files require an intentional `scan.max_file_size` increase.
- Ignored untracked files are excluded by Git's `--exclude-standard` behavior.
- Full unsalted fingerprints make exact local verification possible, but fingerprints of weak values may be guessable; reports must be restricted.
- The persistent cache is opt-in, local, and limited to immutable Git blobs; working-tree files are always rescanned and remediation verification bypasses it. Cache checksums detect corruption but are not authentication, and pathname validation is not an atomic directory-handle sandbox against concurrent path swaps. An enabled cache and its Git directory are trusted local state and must not come from an untrusted/shared location. There is no daemon, central policy service, or web dashboard.

These limits should remain visible in every workflow rather than being hidden behind a single success label.
