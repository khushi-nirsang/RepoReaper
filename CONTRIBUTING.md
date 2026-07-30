# Contributing

## Safety Invariants

- Use fake, nonfunctional token-shaped fixtures only. Never commit or paste a live secret.
- Reports, diagnostics, logs, failure messages, snapshots, and test output must never contain the full captured secret.
- Keep every production Git invocation in `internal/gitrepo`.
- Invoke Git with `os/exec` argument arrays and never through a shell command string.
- Preserve bounded reads and cancellation for Git objects, working-tree files, and embedded content.
- Do not add provider/network validation without an explicit privacy and threat-model review.

## Local Checks

Go 1.24 or newer and Git are required. Run:

```sh
make fmt-check
make vet
make test
make vuln
make build
```

The equivalent direct commands are:

```sh
gofmt -l $(git ls-files --cached --others --exclude-standard '*.go')
go vet ./...
go test -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go build -trimpath ./...
```

The `gofmt -l` command must print no files. It selects tracked and non-ignored untracked project Go files, so ignored build/module caches are not treated as source. In PowerShell, use:

```powershell
$files = git ls-files --cached --others --exclude-standard '*.go'
gofmt -l $files
```

Use `gofmt -w` on the specific changed Go files to fix formatting.

Run the race detector in an environment with CGO and a working C compiler:

```sh
make race
```

The project CI runs the race suite on Linux. A default Windows Go installation without GCC cannot run `go test -race`; that is an environment limitation, not evidence that the race suite passed locally.

Focused fuzzing is available with:

```sh
go test ./internal/detector -run=^$ -fuzz=FuzzBuiltInDetectors -fuzztime=15s
go test ./internal/report -run=^$ -fuzz=FuzzReportEncodersNeverExposeAbsentRawValues -fuzztime=15s
```

## Test Expectations

- Add a regression test for every bug fix and focused unit tests for new behavior.
- Exercise repository behavior with temporary local Git repositories and synthetic content.
- Assert no-raw-secret behavior across table, JSON, HTML, SARIF, verification, hook, and error paths affected by a change.
- Cover malformed objects, hostile paths, cancellation, size limits, and decoder limits when changing Git or content parsing.
- Keep tests deterministic and offline. Do not depend on a real provider, credential, user repository, or remote network service.
- Benchmark changes to the object/tree hot path and document material regressions.

Pull requests are checked on Linux, macOS, and Windows. CI also runs formatting, vet, coverage, Linux race tests, fuzz smoke tests, `govulncheck`, and a GoReleaser snapshot with SBOM generation. CodeQL and dependency review jobs are visibility-gated to public repositories.

## Documentation

Update the README, operating guide, detector reference, report schema, and changelog when a change affects commands, flags, scope, output fields, detector definitions, verification semantics, or safety limits. Claims must distinguish local evidence from provider/remote proof.
