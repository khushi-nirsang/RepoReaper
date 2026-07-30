# Security Policy

## Reporting A Vulnerability

Report vulnerabilities privately to the project maintainer with affected version/commit, impact, and minimal reproduction steps. Do not open a public issue containing exploit details, repository contents, report artifacts, fingerprints, credentials, personal data, or sensitive paths.

RepoReaper does not require a raw secret to diagnose detector or reporting bugs. Use synthetic, nonfunctional token-shaped fixtures and redact repository-specific metadata.

## Sensitive Artifacts

RepoReaper never intentionally serializes the raw captured secret. Before cache persistence and again at the final generated scan-report boundary, exact captured values are scrubbed from string-bearing repository, configuration, finding, evidence, remediation, warning, and notice metadata. Derived fingerprints and detector-signature hashes remain unchanged. Reports nevertheless remain sensitive. JSON contains full unsalted SHA-256 fingerprints for exact verification; a weak password fingerprint may be guessable offline. Reports can also include local paths, commit identities, timestamps, ref names, remote hostnames, and exposure state. The optional persistent cache contains redacted previews, full fingerprints, captured-value byte lengths, paths inside decoded payloads, warnings, and counters, so it is sensitive as well.

Store reports with restricted access, avoid public CI artifacts, and delete them according to the incident's retention policy. Remote URLs are sanitized, but operators should still review unusual URL forms before sharing a report.

## Security Boundaries

RepoReaper:

- reads local repositories, Git objects, refs, the index, and selected working-tree files;
- invokes Git directly without a shell;
- expands supported ZIP, gzip, tar, and Base64 content only in memory with finite per-item, total-byte, depth, and entry limits; ZIP members also have a compression-ratio guard, while gzip output is constrained by the absolute decoded-size and total-byte limits;
- does not upload repository contents, send telemetry, authenticate to providers, rewrite history, delete refs, expire reflogs, run garbage collection, or force-push.

Raw Git blob data and matches exist transiently in process memory while detection runs. The opt-in persistent cache applies only to immutable Git blobs and never stores blob bytes or raw captured matches. It does persist redacted/fingerprint result metadata. Cache files are restricted to `<git-dir>/reporeaper`; existing symlink and Windows reparse-point components are rejected. Those checks are pathname-based rather than an atomic directory-handle sandbox, so adversarial concurrent mutation by a party that can write the Git directory is outside the cache's trust boundary. Cache checksums detect accidental corruption; they are not signatures or message-authentication codes and cannot establish who created a well-formed entry. Enabling the cache therefore treats that dedicated subtree as locally trusted. Do not enable or reuse it for an untrusted or shared Git directory, and remove it before scanning if its provenance is uncertain. Remediation verification bypasses the persistent cache and rescans Git blobs.

Repository scans warn and count skipped top-level files/blobs when the configured size limit or a read/symlink boundary prevents inspection; supported embedded expansion failures also warn. Staged hook mode prints a non-secret warning and fails closed whenever a staged object or supported embedded payload cannot be completely inspected.

## Release Integrity

The tagged-release workflow is configured to build with reproducibility-oriented timestamps and `-trimpath`, produce SHA-256 checksums and SPDX JSON SBOMs, and submit published artifacts for GitHub attestation. Verify the successful workflow run, checksum, and available attestation for the specific release before installing a downloaded binary.

These controls improve supply-chain traceability; they do not replace review of the source, workflow, dependencies, and the identity of the release publisher.
