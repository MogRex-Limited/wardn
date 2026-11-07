# Local equivalents of every CI gate. `make check` must pass before a pull
# request is opened. Tool versions are pinned to match CI exactly.
#
# There are two Go modules: the library (.) and the integration tests
# (tests/integration), which keeps database drivers out of wardn's go.mod.
# Every gate runs on both.

GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION   := v1.9.0

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

INTEGRATION := tests/integration
COMPOSE     := docker compose -f $(INTEGRATION)/compose.yaml

# DSNs for the databases started by `make db-up` (see tests/integration/compose.yaml).
DB_ENV := WARDN_TEST_POSTGRES_DSN='postgres://postgres:wardn@127.0.0.1:56432/wardn?sslmode=disable' \
          WARDN_TEST_MYSQL_DSN='root:wardn@tcp(127.0.0.1:56306)/wardn' \
          WARDN_TEST_MARIADB_DSN='root:wardn@tcp(127.0.0.1:56307)/wardn'

.PHONY: check test test-integration integration db-up db-down lint fmt vuln deps tidy cover hooks

## hooks: install the pre-push hook that runs `make check` (once per clone)
hooks:
	git config core.hooksPath .githooks
	@echo "pre-push hook installed: every push now runs make check"

## check: run every CI gate (run this before opening a pull request)
check: tidy deps lint test test-integration vuln

## test: run the library's tests with the race detector, in random order
test:
	go test -race -shuffle=on -count=1 ./...

## test-integration: run store tests on SQLite, plus any database whose DSN is set
test-integration:
	cd $(INTEGRATION) && go test -race -shuffle=on -count=1 ./...

## integration: start Postgres, MySQL and MariaDB in Docker and run the store tests on all of them
integration: db-up
	cd $(INTEGRATION) && $(DB_ENV) go test -race -shuffle=on -count=1 -v ./... | grep -E '^(---|ok|FAIL|PASS)'

## db-up / db-down: start or stop the integration test databases
db-up:
	$(COMPOSE) up -d --wait
db-down:
	$(COMPOSE) down

## cover: run tests and open a coverage report (includes SQL store coverage from SQLite)
cover:
	go test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

## lint: run all linters, including security linters, on both modules
lint:
	$(GOLANGCI_LINT) run --allow-parallel-runners ./...
	cd $(INTEGRATION) && $(GOLANGCI_LINT) run --allow-parallel-runners ./...

## fmt: format all code
fmt:
	$(GOLANGCI_LINT) fmt ./...
	cd $(INTEGRATION) && $(GOLANGCI_LINT) fmt ./...

## vuln: scan both modules for known vulnerabilities in code paths they use
vuln:
	$(GOVULNCHECK) ./...
	cd $(INTEGRATION) && $(GOVULNCHECK) ./...

## deps: check direct dependencies against each module's allowlist
deps:
	./scripts/check-deps.sh
	./scripts/check-deps.sh $(INTEGRATION) .github/allowed-dependencies-integration.txt

## tidy: check go.mod/go.sum are tidy and module checksums verify, in both modules
tidy:
	go mod tidy -diff
	go mod verify
	cd $(INTEGRATION) && go mod tidy -diff && go mod verify
