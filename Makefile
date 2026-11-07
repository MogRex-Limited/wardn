# Local equivalents of every CI gate. `make check` must pass before a pull
# request is opened. Tool versions are pinned to match CI exactly.

GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION   := v1.9.0

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: check test lint fmt vuln deps tidy cover hooks

## hooks: install the pre-push hook that runs `make check` (once per clone)
hooks:
	git config core.hooksPath .githooks
	@echo "pre-push hook installed: every push now runs make check"

## check: run every CI gate (run this before opening a pull request)
check: tidy deps lint test vuln

## test: run tests with the race detector, in random order
test:
	go test -race -shuffle=on -count=1 ./...

## cover: run tests and open a coverage report
cover:
	go test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

## lint: run all linters, including security linters
lint:
	$(GOLANGCI_LINT) run --allow-parallel-runners ./...

## fmt: format all code
fmt:
	$(GOLANGCI_LINT) fmt ./...

## vuln: scan for known vulnerabilities in code paths wardn actually uses
vuln:
	$(GOVULNCHECK) ./...

## deps: check direct dependencies against the allowlist
deps:
	./scripts/check-deps.sh

## tidy: check go.mod/go.sum are tidy and module checksums verify
tidy:
	go mod tidy -diff
	go mod verify
