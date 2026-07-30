# Architecture

RepoReaper is organized around a local, read-only scan pipeline:

```text
Cobra CLI
   |
   +--> configuration / detector registry
   |
   +--> Git repository adapter --> refs, graph, batch objects, worktree
   |                                  |
   |                                  v
   +----------------------------> scanner coordinator
                                      |
                         +------------+-------------+
                         |                          |
                  content expansion           detector checks
                         |                          |
                         +------------+-------------+
                                      |
                              finding aggregation
                                      |
                         timeline + risk + ref inference
                                      |
                         table / JSON / HTML / SARIF
```

## Package Boundaries

- `cmd/` owns Cobra command wiring, configuration overrides, allowlists, policy exits, diagnostics, shell-completion generation, and process exit-code mapping.
- `internal/gitrepo` is the only production package that invokes Git. It always uses `os/exec` with an argument array and never constructs a shell command.
- `internal/content` performs bounded, in-memory ZIP, gzip, tar, and Base64 expansion.
- `internal/detector` owns candidate generation, offline validation, redaction, fingerprints, and detector signatures.
- `internal/scanner` coordinates index enumeration, working-tree reads, Git-object workers, content expansion, deduplication, the optional persistent blob-result cache, finding aggregation, and evidence attachment.
- `internal/timeline` derives graph-aware introduction, removal, reintroduction, and open intervals.
- `internal/risk` computes deterministic scores from severity and exposure metadata.
- `internal/report` serializes table, JSON, self-contained HTML, and SARIF output.
- `internal/investigate` renders a safe explanation of a JSON scan report.
- `internal/verify` creates a broad reproduction scope and compares fingerprint evidence without requiring the original secret.
- `internal/protect` manages the owned hook and scans index blobs through bounded batch reads and the shared content-expansion layer.

## Git Object Strategy

Git remains the authority for repository discovery, refs, commit graph, reachability, reflogs, and object streams. RepoReaper reads raw tree objects supplied by Git and parses their length-delimited entries inside `internal/gitrepo`.

One scan-local tree walker caches shared tree objects across commits. Blob workers each own a persistent `git cat-file --batch` process, so a large history does not start a new Git process for every blob. Blob object IDs are deduplicated before detection; one detection result can then be attached to every commit/path evidence record that references the blob.

Ref containment is queried only for timeline introduction and residual commits and cached per commit. If the batch tree reader cannot be opened, the scanner falls back to individual `git ls-tree` commands and emits a warning. A tree/object read failure is a coverage warning, not silent success.

The batch protocol accepts only validated SHA-1 or SHA-256 hexadecimal object IDs, bounds every body read, and drains oversized bodies to preserve stream alignment. Git is invoked directly without a shell.

The opt-in persistent cache sits after immutable Git-blob reads and content detection. Its semantic namespace hashes the active detector matching definitions, content-expansion version, cache-result semantics version, and size limit. It stores only validated redacted/fingerprint match metadata, warnings, and counters. Working-tree reads are never cached. Cache files are bounded, versioned, per-entry checksummed, owner-restricted where the platform supports it, atomically replaced, and restricted to a dedicated RepoReaper subtree inside the repository Git directory. Existing symlink and Windows reparse-point path components are rejected. Corrupt or incompatible entries miss and rescan; cache operational failures are notices rather than evidence-coverage warnings.

The checksum is an accidental-corruption control, not authentication. When ordinary scans enable the cache, the dedicated cache subtree is part of the locally trusted Git-metadata boundary. Verification deliberately bypasses it and rescans blobs, because an unauthenticated cached negative result must not establish remediation.

## Working-Tree Boundary

Working-tree reads are confined to paths returned by `git ls-files`. The normal scan reads tracked paths; `--include-untracked` adds `git ls-files --others --exclude-standard`, so ignored files remain excluded. File opening verifies that the resolved path stays under the repository root, and symlinks are not followed.

The Git index and working tree are scanned independently of commit date filters. Every index stage is inspected, including unresolved merge stages; each evidence record retains its stage. Direct refs that point to blobs or trees are walked even though `git rev-list` only accepts commit roots. Evidence records distinguish index, direct-ref, tracked-working-tree, and untracked origin.

Bare repositories use their absolute Git directory as the scan root and skip index and working-tree reads. History, refs, reflogs, and unreachable objects remain available. The report records `bare: true`, `index_ok: false`, and `worktree_ok: false` so consumers do not mistake the intentional absence of those scopes for an ordinary coverage failure.

## Content Safety

Content expansion writes no extracted data to disk. It uses per-unit, total-byte, entry-count, and nesting-depth limits. ZIP members also have a compression-ratio guard; gzip output is bounded by absolute decoded-size and total-byte limits rather than a ratio heuristic. Unsafe archive member paths, directories, and symlinks are skipped. Unsupported binary content is ignored rather than passed to regex detectors.

Raw blob data and detector captures necessarily exist transiently in process memory while scanning. Before aggregation, a capture scrubber removes every exact captured value from content-derived result metadata. A final scan-report pass applies the same proof-based scrubber to string-bearing configuration, repository, finding, nested evidence, remediation, warning, and notice metadata; fingerprints and detector-signature hashes remain unchanged. Findings retain a redacted preview and SHA-256 fingerprint, not the raw capture. When the optional persistent cache is enabled, it persists only sanitized result metadata, fingerprints, and the captured-value byte length needed to scrub cache-hit evidence; it never persists raw blob data or raw captures.

## Aggregation And Provenance

The aggregation key is the full SHA-256 fingerprint of the detector's captured secret value. If more than one detector accepts the same value, the higher-severity detector supplies the primary classification. Evidence remains attached across index stages, working-tree paths, commits, refs, reflogs, unreachable objects, and decoded payload locations.

Logical archive paths use `!` separators. Decoder provenance uses `+` chains such as `utf-16le`, `zip`, or `base64+utf-16be`. Findings retain separate booleans for HEAD, index, direct ref objects, tracked working tree, untracked files, reflogs, and unreachable objects even when `current_status` presents only the highest-priority label.

## Timeline And Risk

The timeline engine consumes the selected commit DAG and a per-fingerprint presence map. It records every transition from absence to presence and every removal boundary. Concurrent branch intervals remain separate, and overlapping exposure time is unioned before risk scoring. A merge with mixed parent presence is intrinsically ambiguous and lowers confidence.

Date-filtered or locally incomplete history can still distort the apparent introduction. Warnings and confidence must be evaluated with the timeline.

## Verification Model

Verification loads the baseline before scanning and requests a conservative superset of its local scope: all refs (including direct object refs), branches, tags, reflogs, unreachable objects, and non-ignored untracked files, without date/severity/detector filters. It bypasses the optional persistent cache and compares only full fingerprints.

Detector signatures bind absence verification to the relevant regex, keywords, entropy threshold, and structural-validator version. Scope gaps, rule drift, shallow history, and current scan warnings produce exit code `3` rather than an unsupported pass.

New reports use schema 1.1. Verification accepts a legacy 1.0 baseline but does not invent missing detector/provenance metadata; those omissions can make the relevant conclusion incomplete.

This model can establish only "not observed in the complete local scope." It cannot establish credential revocation or deletion from a server or another clone.

The separate `scan --baseline` path is intentionally narrower and implemented in `cmd/`. It indexes baseline findings by detector ID plus full fingerprint, normalizes logical paths, and suppresses a current finding only when its path set and current/residual scope have not expanded. Safe network remote identities reject a clear cross-repository mismatch. It does not broaden scan scope or check detector signatures and therefore must not be used as remediation verification.

## Output Boundary

Report serialization never receives a raw detector value. HTML escapes dynamic content, SARIF uses a short partial fingerprint, and JSON retains the full fingerprint needed for verification. Report writes use a restrictive temporary file and atomic rename where available.

Remote URLs are sanitized before entering the report. Reports still include repository paths, commit author identities, ref names, timestamps, and security findings, so they remain sensitive artifacts.
