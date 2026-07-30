# Report Schema

Only a RepoReaper JSON **scan report** can be used as a CI or remediation-verification baseline; table, HTML, SARIF, and verification-result JSON are not baseline formats. Newly generated scan reports identify themselves with `document_type: "scan-report"` and use `schema_version: "1.1"`.

```sh
reporeaper scan . --format json --output baseline.json
reporeaper investigate --report baseline.json
reporeaper verify . --baseline baseline.json --format json --output verification.json
```

Consumers should reject unsupported schema values and document types, while ignoring additive fields they do not use. `investigate`, `verify`, and `scan --baseline` accept complete current `1.1` and legacy `1.0` scan reports. Older supported reports that predate `document_type` are structurally validated instead of being mistaken for verification results or schema-only JSON.

## Scan Report

Top-level fields are:

| Field | Meaning |
| --- | --- |
| `document_type` | `scan-report` for newly generated scan reports |
| `schema_version` | Report contract version, currently `1.1` |
| `tool_version` | RepoReaper build version |
| `generated_at` | UTC report generation time |
| `scan_config` | Effective evidence scope, resource settings, filters, and detector signatures |
| `repository` | Local repository identity and sanitized remote metadata |
| `findings` | Findings aggregated by exact secret fingerprint |
| `summary` | Counts after allowlist/baseline suppression and severity filtering |
| `stats` | Work and content-expansion counters |
| `warnings` | Conditions that reduced or may have reduced coverage |
| `notices` | Operational conditions that did not reduce evidence coverage, such as an optional-cache write miss |

When `scan --baseline` is used, the emitted document is still a normal scan report containing only remaining current findings. `summary.suppressed_findings` is the combined suppression total; `summary.allowlist_suppressed` and `summary.baseline_suppressed` identify each source.

### Scan Configuration

`scan_config` records `include_untracked`, `branches`, `tags`, `all_refs`, `unreachable`, `reflogs`, `workers`, `max_file_size`, `cache_enabled`, optional severity/detector/date filters, and `detector_signatures`. Cache paths and limits are intentionally not serialized because they are execution-local rather than evidence scope.

`detector_signatures` maps active detector IDs to signatures over their matching definition. Verification uses this map to reject unsupported absence claims after a rule changes or disappears. A baseline produced before signatures were recorded is still valid JSON, but absence verification for its findings is incomplete.

Dates are serialized as normalized RFC 3339 boundaries even though the CLI accepts `YYYY-MM-DD`.

### Repository

Repository metadata includes the resolved path, Git directory, HEAD, current branch, `bare` status, shallow-clone status, index/working-tree availability, and remotes. A non-bare complete scan has `index_ok: true`; an index-enumeration failure sets it false and emits a coverage warning. A bare scan intentionally has `bare: true`, `index_ok: false`, and `worktree_ok: false`. Credentials, query strings, and fragments are removed from parseable remote URLs. SCP-style URLs containing a user prefix are reduced to a redacted user marker.

Remote metadata is descriptive local configuration. It is not evidence that RepoReaper contacted or inspected the server.

### Findings

Each finding is one exact SHA-256 fingerprint and includes:

- detector identity, category, severity, confidence, and confidence reason;
- deterministic risk score and explanation;
- full 64-character SHA-256 `fingerprint` and 12-character `short_fingerprint`;
- a detector-aware `redacted` preview;
- aggregate `current_status` plus explicit index, direct-ref, working-tree, tracked, untracked, HEAD, reflog, and unreachable booleans;
- commit count and estimated union of exposure-interval duration;
- local remote inference and its reason;
- first/last-seen, introduction, removal, intervals, evidence, paths, branches, tags, and remediation.

The full fingerprint is required for exact verification and is never displayed in table, HTML, or SARIF output. It is not a raw secret, but an unsalted hash of a weak password may be guessable offline. Restrict report access accordingly.

`current_status` is a presentation priority. HEAD takes precedence over index, direct-ref objects, and working-tree states. For example, a finding present in both HEAD and an untracked file is labeled `present-in-head`; use the boolean fields and evidence array when every provenance dimension matters. Direct object refs use `present-in-ref-object`.

### Exposure Intervals

Each interval records start/end timestamps, start/end commits, the removal commit when known, and status. More than one interval can represent removal/reintroduction or concurrent branch paths. An absent end time means the interval is still open or historically ambiguous; consult status and confidence rather than assuming continued exposure on every branch.

Estimated duration is the union of overlapping interval ranges, so concurrent branches are not double-counted.

### Evidence And Embedded Provenance

Evidence records source, commit/blob/path/ref, line, author identity, timestamp, and scope flags. The optional `decoder` contains a `+`-joined transformation chain such as `base64`, `zip`, or `gzip+tar`. Before serialization, RepoReaper applies a final proof-based scrub across string-bearing repository, configuration, finding, nested evidence, remediation, warning, and notice metadata. An exact captured-value occurrence is replaced with a fixed redaction marker; fingerprints and detector-signature hashes remain unchanged.

Archive member paths are appended with `!`, for example:

```text
artifacts/bundle.zip!nested/config.env
```

For Base64 content, the evidence line is the encoded candidate's line in the outer text. For an archive member, the line is inside the decoded member.

### Statistics

`stats` contains:

| Field | Meaning |
| --- | --- |
| `duration_millis` | Wall-clock scan duration |
| `objects_scanned` | Working-tree files plus unique Git blob objects processed |
| `objects_skipped` | Top-level working-tree files/Git blobs skipped because a read, size, or symlink boundary prevented inspection |
| `blobs_deduplicated` | Repeated blob evidence locations avoided by object-ID deduplication |
| `commits_analyzed` | Reachable, reflog, and unreachable commits considered |
| `payloads_scanned` | Plain or decoded text units passed to detectors |
| `archives_opened` | ZIP, gzip, or tar containers opened |
| `encoded_payloads_scanned` | Base64 candidates accepted for decoded inspection |
| `bytes_inspected` | Text payload bytes passed through the content layer |
| `trees_read` | Raw Git tree objects read |
| `tree_cache_hits` | Shared tree-object reads served from the scan-local cache |
| `blob_cache_hits` | Immutable Git blob results restored from the optional persistent cache |
| `blob_cache_misses` | Git blobs rescanned because the optional cache had no compatible entry |

Counters describe work performed, not proof of complete coverage. Always evaluate `warnings`. `notices` describe non-coverage operational events and do not by themselves make verification incomplete.

## Verification Report

Verification JSON uses `document_type: "verification-result"` and the current `schema_version: "1.1"`, but has a purpose-specific structure and is never accepted as a scan baseline:

| Field | Meaning |
| --- | --- |
| `document_type` | `verification-result` |
| `schema_version` | Verification result contract version, currently `1.1` |
| `repository` | Current resolved repository path |
| `items` | One result for every baseline finding |
| `passed` | True only when all baseline fingerprints are absent under complete reproducible scope |
| `incomplete` | True when at least one scope or detector gap prevents a conclusion |
| `notes` | Global interpretation and scope notes |

Each item contains:

- `status`: concise overall local evidence result;
- `scope_status` and optional `scope_gaps`;
- `credential_rotation_status`, always `cannot-be-confirmed`;
- independent source, reachable-history, remote-copy, and local-residual statuses;
- safe `supporting_observations`.

Possible overall states include `not-observed`, `unable-to-verify`, `still-in-head`, `still-in-index`, `still-in-ref-object`, `still-in-tracked-working-tree`, `still-in-untracked-file`, `still-in-reachable-history`, `still-in-tags`, `still-in-remote-tracking-refs`, `still-in-reflog`, and `still-in-unreachable-objects`.

`not-observed` means the fingerprint was not found in a complete selected local scan. It does not prove provider revocation, remote deletion, or deletion from every clone. `unable-to-verify` means absence must not be interpreted because scope, objects, warnings, or detector identity were incomplete.

## CI Baseline Versus Verification

Both workflows accept a RepoReaper scan JSON document, but they have different contracts:

| Workflow | Purpose | Scope behavior | Match behavior |
| --- | --- | --- | --- |
| `scan --baseline FILE` | Hide unchanged accepted findings before CI policy | Uses the current scan flags/configuration as supplied | Suppresses same detector/full fingerprint only at known path subsets with no expansion into current/residual scope |
| `verify --baseline FILE` | Establish whether baseline evidence remains after cleanup | Automatically constructs a conservative broad local rescan, bypasses the persistent cache, and checks scope/rule identity | Produces one verification item per baseline finding |

Never interpret CI-baseline suppression as credential revocation or remediation proof.

## Legacy 1.0 Baselines

`investigate`, `verify`, and `scan --baseline` safely parse structurally complete legacy `1.0` scan JSON. Missing 1.1 metadata, including `document_type`, is not invented:

- verification reports missing detector signatures as an incomplete scope gap for affected findings;
- missing index/tracked/untracked/bare provenance retains its zero-value meaning and can limit the conclusion;
- CI baseline suppression still requires a valid detector ID and full SHA-256 fingerprint, and newly observed paths/scopes remain visible under the recorded legacy fields.

Generate new baselines with 1.1 whenever possible. Legacy rendering cannot display metadata that the older report never recorded.

## Other Formats

- Table output is a human summary plus performance, persistent-cache, coverage-warning, and operational-notice statistics.
- HTML is a self-contained, escaped offline report with client-side search, severity filtering, skipped-object/cache counts, coverage warnings, and operational notices.
- SARIF is SARIF 2.1.0 with one result per evidence location, a 12-character partial fingerprint, decoder/source metadata, scanned/skipped/cache run properties, and warnings/notices in `toolExecutionNotifications`.

None of these formats contains the raw captured secret. They can still expose sensitive repository structure, identities, timestamps, and security posture.
