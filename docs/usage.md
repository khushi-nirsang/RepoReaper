# Usage

Run a normal local scan:

```sh
reporeaper scan .
```

Use `--format json|html|sarif --output FILE` for machine-readable or offline reports. Add `--include-untracked`, `--all-refs`, `--reflogs`, and `--unreachable` for a broad forensic baseline:

```sh
reporeaper scan . --include-untracked --all-refs --reflogs --unreachable --format json --output baseline.json
```

`--include-untracked` includes non-ignored files only. The resolvable HEAD commit and tracked working-tree files are scanned even if branch/tag enumeration is disabled.

Enable the bounded, no-raw-content persistent cache for repeated Git-history scans:

```sh
reporeaper scan . --cache
```

The cache is opt-in, applies only to immutable Git blobs, stays in RepoReaper's dedicated subtree inside the repository Git directory, and stores redacted/fingerprint metadata rather than raw content. Its checksum detects corruption but does not authenticate cache authorship, so enable it only for locally trusted Git metadata. Use `--cache-path`, `--cache-max-entries`, and `--cache-max-size` to tune it within that boundary. `verify` bypasses the cache.

Fail CI at a minimum severity and selected evidence scope while still writing the report:

```sh
reporeaper scan . --format sarif --output reporeaper.sarif --fail-on high --fail-scope current
```

Suppress only findings already accepted at the same normalized paths and exposure scopes:

```sh
reporeaper scan . --baseline accepted.json --format sarif --output new-findings.sarif --fail-on high --fail-scope current
```

`scan --baseline` is a CI triage filter. New paths or expansion into HEAD, working-tree, tracked, untracked, reflog, or unreachable scope stay visible. It is not a substitute for `verify`.

Inspect and verify a baseline:

```sh
reporeaper investigate --report baseline.json
reporeaper verify . --baseline baseline.json
```

Check local readiness without scanning secrets:

```sh
reporeaper doctor .
reporeaper doctor . --format json
```

Generate command completion:

```sh
reporeaper completion bash
reporeaper completion zsh
reporeaper completion fish
reporeaper completion powershell
```

Exit codes are:

- `0`: command success, policy not triggered, or complete verification passed.
- `1`: scan policy triggered or complete verification still observes baseline evidence.
- `2`: command, path, configuration, baseline/report, or unhealthy `doctor` error.
- `3`: verification is incomplete and must not be interpreted as pass/fail.
- `4`: unrecoverable scan or Git execution failure.

Diagnostics and explicit `--progress` output go to stderr. Machine-readable report content goes to stdout or the requested restricted output file. A scan policy is evaluated only after its report has been written. Coverage-reducing conditions are `warnings`; optional-cache and similar non-coverage conditions are `notices`.

See the [complete operating guide](guide.md) for scope semantics, embedded-content limits, verification rules, hook behavior, configuration, CI policy, and troubleshooting.
