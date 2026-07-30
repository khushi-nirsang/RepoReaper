BINARY=reporeaper
VERSION?=dev
GO_FILES=$(shell git ls-files --cached --others --exclude-standard '*.go')

.PHONY: build fmt-check test race vet vuln lint clean snapshot

build:
	go build -trimpath -ldflags "-X github.com/khushi/reporeaper/cmd.version=$(VERSION) -X github.com/khushi/reporeaper/cmd.commit=unknown -X github.com/khushi/reporeaper/cmd.buildDate=unknown" -o $(BINARY) .

fmt-check:
	@files="$$(gofmt -l $(GO_FILES))"; test -z "$$files" || (printf '%s\n' "$$files" && exit 1)

test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

lint:
	golangci-lint run

clean:
	go clean
	rm -rf dist $(BINARY) $(BINARY).exe

snapshot:
	goreleaser release --snapshot --clean
