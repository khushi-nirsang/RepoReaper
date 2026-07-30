# RepoReaper Operating Guide

## What RepoReaper Does

RepoReaper answers whether a token, password, private key, or credential-shaped value is present now or remains recoverable from evidence available in a local Git repository. It is an investigation and verification tool, not a credential validator or history rewriter.

The scan pipeline is:

1. Resolve the repository with `git rev-parse`.
2. Enumerate the requested branches, remote-tracking refs, tags, reflogs, and unreachable objects.
3. Walk commit trees, cache shared tree objects, and collect blob object IDs plus evidence metadata.
4. Read unique Git objects through bounded, persistent `git cat-file --batch` workers. Scan every Git-index stage plus tracked and optional non-ignored untracked working-tree files separately without following symlinks. Direct refs to blob/tree objects are inspected too.
5. Decode bounded UTF-16LE/BE text and inspect plain text, then safely expand supported embedded ZIP, gzip, tar, and Base64 content in memory.
6. Run keyword prefilters, regex/format checks, placeholder suppression, entropy checks, and selected offline structural validators. No live credential validation occurs.
7. Hash only the captured secret value with SHA-256, retain a redacted preview, and aggregate evidence by fingerprint.
8. Derive graph-aware introduction, removal, reintroduction, and open exposure intervals. Mixed merge-parent presence lowers timeline confidence because exact attribution is ambiguous.
9. Infer branch, tag, reflog, unreachable-object, and remote-tracking-ref exposure from local Git metadata.
10. Calculate a deterministic risk score and render only redacted results.

## Requirements And Help

RepoReaper requires Go 1.24 or newer to build, and a working `git` executable on `PATH` at runtime.

```sh
go build -o reporeaper .
reporeaper --help
reporeaper scan --help
reporeaper detectors list
reporeaper detectors describe github-token
reporeaper doctor .
reporeaper version
```

On Windows, the default output name is `reporeaper.exe`.

## Diagnose The Environment

`doctor` runs read-only readiness checks for the RepoReaper runtime, active configuration and detector registry, Git availability, repository access, HEAD/branch state, and shallow-clone coverage:

```sh
reporeaper doctor
reporeaper doctor /path/to/repository
reporeaper doctor . --format json
```

The repository argument defaults to `.`. A warning such as an unborn or shallow repository is included in the result but does not make the command unhealthy. Configuration, Git, repository, history-access, or batch object-reader errors set `healthy: false` and exit `2`. `doctor` opens and cleanly closes a Git batch object reader, but it does not perform a secret scan, fetch missing history, test provider access, or prove every individual object is readable.

## Shell Completion

Generate a completion script for Bash, Zsh, Fish, or PowerShell:

```sh
reporeaper completion bash > reporeaper.bash
reporeaper completion zsh > _reporeaper
reporeaper completion fish > reporeaper.fish
reporeaper completion powershell > reporeaper.ps1
```

Source or install the generated file using the selected shell's normal completion mechanism. Generation writes the script to stdout and does not modify shell startup files.

## Choose Scan Scope

The default scan includes every Git-index entry, tracked working-tree files, and history reachable from local branches, remote-tracking branches, and tags:

```sh
reporeaper scan .
```

The scope controls are:

| Option | Evidence added |
| --- | --- |
| `--include-untracked` | Non-ignored untracked working-tree files reported by Git |
| `--branches` | Local and remote-tracking branch history; enabled by default |
| `--tags` | Tagged history; enabled by default |
| `--all-refs` | Every local ref, including ref namespaces outside branches and tags |
| `--reflogs` | Commits still named by local reflogs |
| `--unreachable` | Unreachable commits and blobs reported by `git fsck` |

The resolvable HEAD commit is always included even when `--branches=false --tags=false`; those flags disable branch and tag enumeration, not current-commit history. Every index stage and tracked working-tree file is also always scanned in a non-bare repository. This catches a secret staged in the index even when HEAD and the working-tree copy are clean. `--include-untracked` adds only non-ignored files because RepoReaper uses Git's `--exclude-standard` behavior.

Use a broad forensic scan when investigating cleanup:

```sh
reporeaper scan . \
  --include-untracked \
  --all-refs \
  --reflogs \
  --unreachable \
  --format json \
  --output baseline.json
```

In PowerShell, use a backtick for line continuation or place the command on one line.

`--reflogs` and `--unreachable` are explicit because they can surface locally deleted history. RepoReaper runs neither reflog expiration nor garbage collection. Evidence found only in those sources is still locally recoverable and should be treated as residual exposure.

Limit detector or resource scope with:

```sh
reporeaper scan . --severity high,critical
reporeaper scan . --detector github-token,pem-private-key
reporeaper scan . --since 2025-01-01 --until 2026-01-01
reporeaper scan . --workers 4 --max-file-size 5242880
reporeaper scan . --branches=false --tags=false
```

`--severity` is an exact comma-separated output filter, not a minimum threshold. `private-key` is accepted as a detector group alias for the PEM, OpenSSH, and PGP private-key detectors.

Date arguments use `YYYY-MM-DD`. RepoReaper converts `--since` to the start of that calendar day and `--until` to the end of that day in the machine's local timezone. Date filters apply to commit enumeration, not to the current working-tree scan. They reduce historical evidence and can make timeline conclusions unsuitable as a cleanup baseline.

An empty, unborn repository can be scanned; it simply has no commit history. Bare repositories are also accepted for history/ref/object scans. They report `bare: true`, `index_ok: false`, and `worktree_ok: false`; index, working-tree, and untracked scopes have no content to inspect.

## Embedded And Encoded Content

Repository scans recognize supported payloads by content, not only by file extension:

- ZIP members;
- gzip streams;
- ustar-compatible tar archives, including gzip-to-tar chains;
- standard or URL-safe Base64 text candidates, with or without padding.

Decoded evidence carries both its logical location and decoder chain. For example, `bundle.zip!nested/config.env` with decoder `zip`, or decoder `gzip+tar` for a member reached through a compressed tar stream. For a Base64 candidate, the evidence line points to the encoded value in the outer text.

Expansion is entirely in memory and guarded. Current defaults limit an individual expanded unit to `--max-file-size`, total expanded bytes to eight times that value with a 256 MiB cap, archive entries to 1,000, transformation depth to two, and ZIP member compression ratio to 200:1. Gzip output is guarded by the absolute decoded-size and total-byte limits rather than a ratio heuristic. Unsafe archive member paths and symlinks are skipped. A warning means some content was not inspected.

Top-level repository files/blobs larger than `--max-file-size` are skipped, counted in `stats.objects_skipped`, and produce a coverage warning. Working-tree symlinks, missing/unreadable objects, and failed ref-containment queries also warn instead of silently disappearing. These controls trade completeness for safe resource use. RAR, 7z, encrypted archives, arbitrary encodings, and external decompression are not supported. The pre-commit staged scanner applies the same bounded content expansion to staged blobs and fails closed when an object or supported embedded payload is missing, corrupt, unsafe, oversized, or otherwise not completely inspected.

## Optional Persistent Blob Cache

Repeated history scans can reuse immutable Git-blob detection results:

```sh
reporeaper scan . --cache
reporeaper scan . --cache --cache-max-entries 100000 --cache-max-size 134217728
```

The cache is off by default and never applies to mutable working-tree files. RepoReaper reserves `<git-dir>/reporeaper` as its cache root. Relative cache paths are resolved below that root; absolute paths are accepted only when they also remain below it. Existing symlink or Windows reparse-point path components are rejected. The default is `<git-dir>/reporeaper/blob-scan-cache-v1`. This boundary prevents a committed working-tree file from supplying cache state.

Cache semantics include the object ID, ordered active detector IDs/signatures, maximum file size, detector-result/redaction version, and content-expansion version. A detector order, matching rule, cached-result semantic, limit, or expansion change causes a miss. Entries contain redacted previews, full/short fingerprints, captured-value byte length, detector and decoded-location metadata, generic coverage warnings, and counters. The length plus fingerprint lets a cache hit scrub a captured value from new Git path/ref/author evidence without persisting the value itself. Entries never contain raw blob bytes or raw captured matches. Full fingerprints can still be sensitive for weak values, so cache files use restrictive permissions, bounded atomic replacement, and must not be published.

Invalid entries are discarded and their blobs are rescanned. An unrecognized file is never overwritten. Concurrent writers merge under an atomic lock; lock contention or a write failure does not invalidate the scan result. Those conditions appear as operational `notices`, while only evidence-coverage `warnings` make remediation verification incomplete. `stats.blob_cache_hits` and `stats.blob_cache_misses` show reuse.

The entry checksum is an accidental-corruption check, not authentication. A party able to write the Git directory can forge a structurally valid entry. Path validation is repeated but pathname-based, not an atomic directory-handle sandbox against a concurrent path-swap attacker. Enabling the cache therefore treats the dedicated RepoReaper subtree and its Git directory as trusted local state. Do not enable or reuse it in an untrusted/shared Git directory; remove it to force an ordinary scan to rebuild it. The remediation `verify` command never reads or writes this persistent cache.

## Read A Finding

Each finding represents one unique SHA-256 fingerprint. Important fields are:

- `redacted`: a safe preview, never the original captured value.
- `current_status`: whether evidence is in HEAD, the Git index, a direct blob/tree ref, a tracked working-tree file, an untracked file, reachable history, a reflog, or unreachable objects.
- `introduced` and `removed`: best local commit evidence where the graph permits attribution.
- `exposure_intervals`: separate intervals for removal, later reintroduction, and concurrent branch paths.
- `branches` and `tags`: local refs containing selected introduction or residual evidence commits.
- `remote_status`: inference from local remote-tracking refs, never an unsupported claim about a server.
- `risk_score` and `risk_explanation`: deterministic severity, confidence, reachability, duration, spread, key-type, and residual-object factors.
- `evidence[].decoder`: the transformation chain used to inspect embedded content.

`present-in-head` takes precedence over `present-in-index`, `present-in-ref-object`, and working-tree status when the same fingerprint exists in multiple places. Index, direct-ref, tracked, and untracked provenance remain available in the boolean fields and evidence records.

Warnings are part of the security result. A shallow clone, missing object, inaccessible reflog, skipped archive member, submodule reference, Git LFS pointer, or unreadable file means some expected evidence may not have been inspected. Operational notices describe non-coverage events such as an unavailable optional cache write and do not by themselves invalidate verification.

## Reports

```sh
reporeaper scan . --format table
reporeaper scan . --format json --output report.json
reporeaper scan . --format html --output report.html
reporeaper scan . --format sarif --output report.sarif
```

JSON is the baseline format. HTML is a self-contained offline report with search, severity filtering, timelines, embedded-content provenance, skipped-object count, escaped coverage warnings/notices, risk reasoning, and remediation steps. SARIF 2.1.0 is intended for code-scanning ingestion and carries coverage warnings and operational notices as tool execution notifications plus scanned/skipped/cache counts in run properties. Table output includes scanned/skipped object, payload, archive, decoded-payload, byte, tree-cache, persistent-blob-cache, deduplication, and commit statistics.

Generated scan reports pass through a final proof-based scrub that removes exact captured values from string-bearing repository, configuration, finding, evidence, remediation, warning, and notice metadata. Secret values are not intentionally serialized; fingerprints and detector-signature hashes remain as derived proof values. JSON reports contain full, unsalted SHA-256 fingerprints so later scans can compare exact values. A fingerprint of a weak or guessable password may itself be vulnerable to offline guessing. Reports also contain paths, commit identities, timestamps, and sanitized remote URLs. Treat every format as restricted security metadata.

Files are created through an owner-mode temporary file and atomic replacement where the platform supports it; Windows uses the platform replacement primitive for existing destinations. Effective ACLs still depend on the parent directory.

## CI Policy Gates

`--fail-on` sets a minimum finding severity and `--fail-scope` selects the evidence class that can fail the command:

| Scope | Matches |
| --- | --- |
| `current` | HEAD, Git-index, tracked working-tree, or included untracked-file evidence |
| `reachable` | HEAD, a direct ref object, or reachable commit, branch, or tag evidence |
| `residual` | Reflog or unreachable-object evidence |
| `any` | Any finding in the produced report |

```sh
reporeaper scan . \
  --include-untracked \
  --all-refs \
  --format sarif \
  --output reporeaper.sarif \
  --fail-on high \
  --fail-scope current
```

RepoReaper writes the report before returning policy exit code `1`, so CI can retain it using a restricted artifact step that runs even after failure. Allowlists and accepted-baseline suppression are applied before policy evaluation. `--severity` affects report presentation only and cannot hide an otherwise policy-eligible finding.

The equivalent configuration is:

```yaml
policy:
  fail_on: high
  scope: current
```

Use `reachable` when new or existing committed history must fail the job, and `residual` for cleanup checks on a local clone. Remote service deletion still cannot be proven.

## Compare New Findings To A CI Baseline

Use an earlier RepoReaper JSON report to remove unchanged accepted findings before policy evaluation:

```sh
reporeaper scan . \
  --include-untracked \
  --baseline accepted.json \
  --format sarif \
  --output new-findings.sarif \
  --fail-on high \
  --fail-scope current
```

A current finding is suppressed only when all of these are true:

- detector ID matches;
- the full 64-character SHA-256 fingerprint matches (short display fingerprints are never accepted);
- every normalized current path is in the baseline finding's path set;
- current evidence has not expanded into HEAD, the Git index, direct ref objects, working tree, tracked working tree, untracked files, reflogs, or unreachable objects relative to the baseline.

Removing an old path does not make an otherwise unchanged finding new. Copying the same credential to a new path, reintroducing it into current source, or expanding it into a previously clean reflog/unreachable scope keeps the complete current finding visible and policy-eligible.

The baseline loader rejects an unsupported schema, missing detector identity, invalid/non-full fingerprint, and an unambiguous mismatch when both reports have non-local network remote identities. Checkout paths and machine-local remotes are not used as repository identity. If either report has no comparable network remote, operators remain responsible for selecting the correct baseline.

Allowlist suppression occurs first. Baseline suppression occurs next, followed by the exact `--severity` filter and policy evaluation. `summary.suppressed_findings` is the total; `allowlist_suppressed` and `baseline_suppressed` preserve the individual counts.

Run the comparison with the same or broader ref, untracked, reflog, unreachable, detector, date, and file-size scope used for the accepted report. `scan --baseline` does not automatically reproduce scope and does not validate detector signatures. It is a noise-reduction/new-finding control, not evidence of remediation. Use `verify --baseline` for the conservative cleanup workflow.

## Investigate And Remediate

```sh
reporeaper investigate --report baseline.json
reporeaper investigate --report baseline.json --finding RR-0001
```

Follow the displayed order: rotate or revoke first, review provider logs, update legitimate deployments, remove current source references, decide whether authorized history rewriting is necessary, coordinate before rewriting shared history, and then verify. RepoReaper only recommends cleanup actions; it does not execute them.

## Verify Cleanup

```sh
reporeaper verify . --baseline baseline.json
reporeaper verify . --baseline baseline.json --format json --output verification.json
```

Verification first loads the baseline, then constructs a conservative local rescan:

- non-ignored untracked files, branches, tags, all refs, reflogs, and unreachable objects are enabled;
- baseline date, severity, and detector-selection filters are removed;
- the file-size limit is at least as large as the valid baseline/configured limit;
- configured built-in detector disabling is ignored;
- the optional persistent blob cache is bypassed, so every Git blob is read and detected again;
- fingerprints are compared without requiring the original secret.

Every detector records a signature derived from its ID, regex, keyword prefilters, entropy threshold, and structural-validator version. If the baseline lacks a signature, the detector is unavailable, or its signature changed, RepoReaper marks that finding's scope incomplete. An absent fingerprint is then `unable-to-verify`; a fingerprint that is still observed remains reported with its current location status and the incomplete-scope warning. Keep baseline custom detectors in the current `.reporeaper.yaml`.

Any current scan warning, a shallow clone, unavailable index or working tree, invalid baseline scope metadata, narrower scope, repository-identity mismatch, malformed full fingerprint, or detector mismatch prevents an unsupported verification pass. Operational notices do not reduce evidence coverage. When a fingerprint remains, verification reports independent current-source, reachable-history, local remote-tracking, reflog, and unreachable-object observations. Credential rotation always remains `cannot-be-confirmed`.

Exit codes are:

- `0`: no baseline fingerprint was observed and every baseline finding had complete reproducible local coverage.
- `1`: one or more baseline fingerprints remain and scope was complete.
- `2`: command, path, baseline schema, report, or configuration error.
- `3`: verification is incomplete; this takes precedence over an ordinary pass/fail conclusion.
- `4`: unrecoverable scan or Git execution failure.

`not-observed` is a local evidence statement, not proof of revocation, remote deletion, or removal from another clone.

## Pre-Commit Protection

```sh
reporeaper protect status
reporeaper protect install
reporeaper protect staged
reporeaper protect uninstall
```

The managed hook calls `reporeaper protect staged`, so the installed binary must remain available on the hook process's `PATH`. It blocks findings only when both conditions hold:

- severity is `high` or `critical`; and
- confidence is `high` or `confirmed`.

It reads index object IDs through a bounded `git cat-file --batch` process and scans index blobs, not unstaged working-tree content. Supported ZIP, gzip, tar, and Base64 payloads receive the same bounded in-memory expansion as repository scans, and decoded paths/decoder chains are included in evidence.

The hook fails closed when any staged Git object or embedded payload cannot be completely inspected, including missing objects, `scan.max_file_size` violations, malformed archives, unsafe members, expansion-depth/entry/byte limits, and compression-ratio guards. Safe warnings are printed to stderr before the nonzero exit. If a legitimate staged file exceeds the configured limit, raise `scan.max_file_size` intentionally after considering hook memory/latency rather than bypassing protection.

Staged protection honors disabled/custom detectors plus applicable fingerprint, path, and safe-metadata regex allowlists. Commit allowlists cannot match index-only evidence because it has no commit identity. Bare repositories have no index/worktree protection scope.

RepoReaper refuses to overwrite or remove a foreign hook. `protect install --force` only repairs a hook already recognized as RepoReaper-managed.

## Configuration And Allowlists

RepoReaper loads `.reporeaper.yaml` from the process's current directory, not automatically from the target repository path. Use the persistent `--config FILE` flag when invoking it elsewhere. Validate before scanning:

```sh
reporeaper config validate --config .reporeaper.yaml
```

A complete example is:

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
  fail_on: high
  scope: current
allowlist:
  fingerprints: []
  paths:
    - "testdata/**"
  commits: []
  regexes: []
detectors:
  disabled: []
  custom:
    - id: widget-token
      name: Widget token
      description: Organization-specific Widget credential
      regex: 'WIDGET_[A-Z0-9]{24}'
      severity: high
      remediation: Rotate the Widget credential.
      keywords: ["WIDGET_"]
      minimum_entropy: 2.5
```

Configuration parsing rejects unknown YAML fields, invalid severities/formats, duplicate detector IDs, invalid regular expressions, unsafe worker/file-size/cache limits, NUL-containing cache paths, and `report.redact: false`.

Allowlists can suppress:

- an exact full or 12-character display fingerprint;
- paths matching a repository-relative glob, but only when every path on the aggregated finding matches;
- commits, but only when all evidence is commit-bound and every evidence commit is listed;
- regular expressions over safe metadata consisting of detector ID, redacted preview, and paths.

Allowlists never evaluate raw secret values. Prefer exact fingerprints or narrow paths. Broad path or regex allowlists can hide future exposures, and allowlisted findings are removed before report summaries and CI policy evaluation.

## Troubleshooting

- Run with `--progress` to send explicit progress messages to stderr. A terminal stderr enables progress automatically.
- Keep stdout reserved for the selected report; send machine-readable output to `--output` in automation.
- Enable `--cache` only when repeated Git-history scans justify trusted local sensitive metadata. Cache failures are safe misses; a stale `.lock` directory can prevent writes until the owning process is confirmed stopped and the lock is removed. Delete the dedicated cache rather than trusting it when provenance is uncertain.
- Increase `--max-file-size` only when the repository and memory budget justify it. The maximum accepted value is 1 GiB, while total embedded expansion remains capped at 256 MiB per scanned object.
- If staged protection rejects a legitimate oversized object, change `scan.max_file_size` in the validated configuration deliberately; the hook has no per-invocation size flag.
- If a verification returns `3`, write JSON output and inspect `notes`, each item's `scope_gaps`, and the scan warnings rather than treating it as a failed cleanup.
- Fetch missing history and tags before a forensic baseline. Git LFS and submodule contents must be materialized and scanned separately.
