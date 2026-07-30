# Security Model

RepoReaper is intended for repositories the user owns or is authorized to inspect.

## Local-First Boundary

RepoReaper reads local Git metadata, objects, index content, and selected working-tree files. It does not upload repository content, send telemetry, validate credentials with providers, fetch remotes, rewrite history, delete refs, expire reflogs, run garbage collection, or force-push.

Remote exposure is inferred only from local remote-tracking refs. Sanitized remote URLs can identify repository configuration but are not proof that a server was contacted.

## Process And Filesystem Boundary

Production Git execution is confined to `internal/gitrepo`. Git is invoked directly with an executable plus argument array, never through a shell command string. Object IDs sent to the batch protocol must be 40- or 64-character hexadecimal values.

Working-tree candidates come from `git ls-files`. Ignored untracked files are excluded, repository-relative paths are confined to the resolved worktree, and symlinks are not followed. Bare repositories skip working-tree/index scope.

## Resource Boundary

Git blob and index-content reads are bounded by `scan.max_file_size`; raw Git tree reads use a separate fixed bound. UTF-16 decoding and ZIP, gzip, tar, and Base64 expansion occurs only in memory and enforces per-unit, total-byte, entry-count, and nesting-depth limits. ZIP members and gzip streams additionally have compression-ratio guards. Unsafe archive paths and symlinks are skipped.

A repository scan records a warning when supported embedded content cannot be completely inspected. Top-level files/blobs above `scan.max_file_size`, working-tree symlinks, missing/unreadable objects, and failed ref-containment queries are skipped with a warning; skipped top-level objects/files are counted in `stats.objects_skipped`. Verification reproduces at least the baseline size limit and treats every current warning as incomplete. Staged protection prints safe warnings and fails closed when a staged object or supported embedded payload cannot be fully inspected. Operators must raise `scan.max_file_size` intentionally for a legitimate large staged object.

## Secret Lifecycle

Raw blob bytes and captured matches exist transiently in process memory while detection runs. A capture scrubber removes exact captured values from content-derived result metadata before aggregation. A final scan-report pass applies the same proof-based scrubber across string-bearing configuration, repository, finding, nested evidence, remediation, warning, and notice metadata. Fingerprints and detector-signature hashes remain unchanged; report serializers receive sanitized metadata and proof values, not raw captures.

The persistent Git-blob cache is opt-in. It never stores blob bytes or raw captured matches. It stores detector identity, redacted preview, full/short fingerprint, captured-value byte length, decoded provenance, generic warnings, and scan counters. The byte length and fingerprint allow cache-hit evidence to be scrubbed without storing the captured value. Its semantic key binds the object ID to ordered detector matching signatures, content-expansion behavior, the configured size limit, and the cache-result semantics version. Malformed, incompatible, or unrecognized entries are never used as clean evidence; affected blobs are rescanned.

Cache paths are restricted to RepoReaper's dedicated subtree under the repository Git directory, preventing a committed working-tree file from supplying cache state. Existing symlink and Windows reparse-point path components are rejected before use and checked again after directory creation. Files are bounded, versioned, checksummed, written through restrictive temporary files and atomic replacement, and coordinated with an exclusive lock directory. A cache read/write/lock failure is an operational notice and a safe miss, not a coverage gap. The cache still contains sensitive full fingerprints; access must be restricted and Windows protection inherits important behavior from the parent ACL.

The per-entry checksum detects accidental corruption, not malicious tampering. It is not keyed and does not authenticate the entry's author or prove that cached metadata came from the named blob. Path validation is repeated before use and after directory creation, but it is pathname-based rather than an atomic directory-handle sandbox; adversarial concurrent path mutation by a party with Git-directory write access is outside the boundary. Enabling the cache treats the dedicated RepoReaper cache subtree and its Git directory as locally trusted state; do not use a cache from an untrusted or shared Git directory. `verify` bypasses the persistent cache and reads Git blobs again so cached negative results cannot support an absence claim.

The JSON verification fingerprint is an unsalted SHA-256 hash of the captured value. This enables exact cross-scan comparison, but a low-entropy password may be guessable offline. Every report remains sensitive even though it contains no intentional raw secret.

## Trust And Completeness

RepoReaper treats local Git as the source of graph, ref, reflog, and object evidence. It cannot inspect:

- objects already garbage-collected or absent from a shallow/partial local clone;
- deleted remote refs or objects that are not represented locally;
- Git LFS content that has not been materialized;
- nested submodule repositories unless they are scanned separately;
- unsupported, encrypted, or limit-exceeding embedded formats.

It also cannot determine whether a credential is live, revoked, expired, scoped, or previously abused. Detector results are heuristic and can be false positives or false negatives.

Warnings, scope metadata, detector signatures, and verification exit code `3` exist to prevent those limits from being collapsed into an unsupported success claim.
