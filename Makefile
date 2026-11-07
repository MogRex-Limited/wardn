# Local equivalents of every CI gate. `make check` must pass before a pull
# request is opened. Tool versions are pinned to match CI exactly.
#
# wardn is several Go modules, so heavy dependencies reach only the users who
# choose them:
#   .                  the library (standard library + YAML only)
#   store/mongo        MongoDB store
#   cache/redis        Redis cache
#   tests/integration  SQL and HTTP tests against real databases and chi
# Every gate runs on every module.

GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION   := v1.9.0

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

MODULES     := . store/mongo cache/redis tests/integration
INTEGRATION := tests/integration
COMPOSE     := docker compose -f $(INTEGRATION)/compose.yaml

# allowlist for a module directory: . → allowed-dependencies.txt,
# store/mongo → allowed-dependencies-store-mongo.txt, and so on.
allowlist = .github/allowed-dependencies$(if $(filter .,$(1)),,-$(subst /,-,$(1))).txt

# Connection settings for the databases started by `make db-up`
# (see tests/integration/compose.yaml).
DB_ENV := WARDN_TEST_POSTGRES_DSN='postgres://postgres:wardn@127.0.0.1:56432/wardn?sslmode=disable' \
          WARDN_TEST_MYSQL_DSN='root:wardn@tcp(127.0.0.1:56306)/wardn' \
          WARDN_TEST_MARIADB_DSN='root:wardn@tcp(127.0.0.1:56307)/wardn' \
          WARDN_TEST_MONGO_URI='mongodb://127.0.0.1:56017' \
          WARDN_TEST_REDIS_ADDR='127.0.0.1:56379'

.PHONY: check test test-modules integration db-up db-down lint fmt vuln deps tidy cover hooks mutation fuzz

## hooks: install the pre-push hook that runs `make check` (once per clone)
hooks:
	git config core.hooksPath .githooks
	@echo "pre-push hook installed: every push now runs make check"

## check: run every CI gate (run this before opening a pull request)
check: tidy deps lint test test-modules vuln

## test: run the library's tests with the race detector, in random order
test:
	go test -race -shuffle=on -count=1 ./...

## test-modules: test the other modules (SQLite always; other databases when their settings are set)
test-modules:
	@for m in $(filter-out .,$(MODULES)); do echo "== $$m"; (cd $$m && go test -race -shuffle=on -count=1 ./...) || exit 1; done

## integration: start every test database in Docker and run all module tests against them
integration: db-up
	@for m in $(filter-out .,$(MODULES)); do echo "== $$m"; (cd $$m && $(DB_ENV) WARDN_TEST_REQUIRE_ALL=1 go test -race -shuffle=on -count=1 ./...) || exit 1; done

## db-up / db-down: start or stop the integration test databases
db-up:
	$(COMPOSE) up -d --wait
db-down:
	$(COMPOSE) down

## cover: run the library's tests and open a coverage report
cover:
	go test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

## lint: run all linters, including security linters, on every module
lint:
	@for m in $(MODULES); do echo "== $$m"; (cd $$m && $(GOLANGCI_LINT) run --allow-parallel-runners ./...) || exit 1; done

## fmt: format all code
fmt:
	@for m in $(MODULES); do (cd $$m && $(GOLANGCI_LINT) fmt ./...) || exit 1; done

## vuln: scan every module for known vulnerabilities in code paths it uses
vuln:
	@for m in $(MODULES); do echo "== $$m"; (cd $$m && $(GOVULNCHECK) ./...) || exit 1; done

## deps: check each module's direct dependencies against its allowlist
deps:
	@$(foreach m,$(MODULES),./scripts/check-deps.sh $(m) $(call allowlist,$(m)) || exit 1;)

## tidy: check go.mod/go.sum are tidy and module checksums verify, in every module
tidy:
	@for m in $(MODULES); do (cd $$m && go mod tidy -diff && go mod verify) || exit 1; done

## mutation: break each security rule in turn and check a test catches it (~2 min)
mutation:
	python3 scripts/mutate.py

## fuzz: run every fuzz target (FUZZTIME each, default 60s)
fuzz:
	./scripts/fuzz.sh $(or $(FUZZTIME),60s)
