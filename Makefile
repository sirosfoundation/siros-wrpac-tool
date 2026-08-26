BINARY     := siros-wrpac-tool
MODULE     := github.com/sirosfoundation/siros-wrpac-tool
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -ldflags "-X $(MODULE)/cmd/siros-wrpac-tool/cmd.Version=$(VERSION) \
              -X $(MODULE)/cmd/siros-wrpac-tool/cmd.Commit=$(COMMIT) \
              -X $(MODULE)/cmd/siros-wrpac-tool/cmd.BuildTime=$(BUILD_TIME)"

.PHONY: build test coverage lint fmt vet tidy clean help

build: ## Build siros-wrpac-tool binary
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/siros-wrpac-tool

test: ## Run tests
	go test -v -race ./...

coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

lint: ## Run linter
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...
	goimports -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy go modules
	go mod tidy

clean: ## Remove build artifacts
	rm -rf bin/ out/ coverage.out

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
