# The gateway builds with the Go toolchain alone. Dependencies are vendored, so
# a box with no working internet — which is the normal state of a gateway being
# repaired — can still build the binary that fixes it.

GO      ?= go
BINARY  ?= bin/gw
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build
build: ## Build the gw binary (static, dependencies vendored)
	CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/gw

.PHONY: test
test: ## Run the Go suite
	$(GO) test -mod=vendor ./...

.PHONY: race
race: ## Run the Go suite under the race detector
	$(GO) test -mod=vendor -race ./...

.PHONY: check
check: ## vet, gofmt and the full suite
	$(GO) vet -mod=vendor ./...
	@unformatted=$$(gofmt -l cmd internal *.go); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) test -mod=vendor ./...

.PHONY: dashboard
dashboard: ## Rebuild the web dashboard (needs Node; the box never does this)
	cd dashboard && npm ci && npm run build

.PHONY: golden
golden: ## Regenerate the renderer's golden files — only ever deliberately
	$(GO) test -mod=vendor ./internal/render/ -run TestBuildTree -update
	@: > tests/testdata/golden-modes.txt
	@for d in tests/testdata/golden/*/; do \
	  n=$$(basename $$d); \
	  (cd $$d && find . -type f -printf '%m\t%P\n' | sort -k2) \
	    | sed "s|^|$$n\t|" >> tests/testdata/golden-modes.txt; \
	done
	@echo "goldens regenerated — read the diff before committing it"

.PHONY: offline
offline: ## Prove the build needs no network
	CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off $(GO) build -o /dev/null ./cmd/gw
	@echo "builds with GOPROXY=off"

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
