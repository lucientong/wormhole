# Wormhole - Zero-config tunnel tool
# Build variables
BINARY_NAME := wormhole
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X github.com/wormhole-tunnel/wormhole/pkg/version.Version=$(VERSION) \
	-X github.com/wormhole-tunnel/wormhole/pkg/version.Commit=$(COMMIT) \
	-X github.com/wormhole-tunnel/wormhole/pkg/version.BuildTime=$(BUILD_TIME)"

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Directories
CMD_DIR := ./cmd/wormhole
PKG_DIR := ./pkg/...
INTERNAL_DIR := ./internal/...
WEB_DIR := ./web
DIST_DIR := ./dist

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: all build build-all clean test test-coverage lint fmt proto web help

## Default target
all: lint test build

## Build the binary for current platform (includes web UI)
build: web
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(DIST_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "$(GREEN)Build complete: $(DIST_DIR)/$(BINARY_NAME)$(NC)"

## Build for all platforms
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "$(GREEN)Building for Linux (amd64)...$(NC)"
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	@echo "$(GREEN)Building for Linux (arm64)...$(NC)"
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

build-darwin:
	@echo "$(GREEN)Building for macOS (amd64)...$(NC)"
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	@echo "$(GREEN)Building for macOS (arm64)...$(NC)"
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

build-windows:
	@echo "$(GREEN)Building for Windows (amd64)...$(NC)"
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

## Run the server
run-server:
	@echo "$(GREEN)Starting server...$(NC)"
	$(GOCMD) run $(CMD_DIR) server

## Run the client
run-client:
	@echo "$(GREEN)Starting client...$(NC)"
	$(GOCMD) run $(CMD_DIR) client

## Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning...$(NC)"
	@rm -rf $(DIST_DIR)
	@rm -rf coverage.out coverage.html
	@find ./pkg/web/dist -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
	@echo "$(GREEN)Clean complete$(NC)"

## Run tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(GOTEST) -v -race $(PKG_DIR) $(INTERNAL_DIR)

## Run tests with coverage
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic $(PKG_DIR) $(INTERNAL_DIR)
	@$(GOCMD) tool cover -func=coverage.out
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

## Run benchmarks
bench:
	@echo "$(GREEN)Running benchmarks...$(NC)"
	$(GOTEST) -bench=. -benchmem $(PKG_DIR)

## Run linter
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

## Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	$(GOFMT) -s -w .

## Generate protobuf files
proto:
	@echo "$(GREEN)Generating protobuf files...$(NC)"
	@./scripts/gen-proto.sh

## Build web UI (outputs to pkg/web/dist/ for Go embed)
web:
	@echo "$(GREEN)Building web UI...$(NC)"
	@cd $(WEB_DIR) && npm install && npm run build
	@echo "$(GREEN)Web UI build complete -> pkg/web/dist/$(NC)"

## Download dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy

## Verify dependencies
verify:
	@echo "$(GREEN)Verifying dependencies...$(NC)"
	$(GOMOD) verify

## Docker build
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t wormhole:$(VERSION) -f deployments/docker/Dockerfile .

## Docker compose up
docker-up:
	@echo "$(GREEN)Starting Docker compose...$(NC)"
	docker-compose -f deployments/docker/docker-compose.yml up -d

## Docker compose down
docker-down:
	@echo "$(YELLOW)Stopping Docker compose...$(NC)"
	docker-compose -f deployments/docker/docker-compose.yml down

## Install to GOPATH/bin
install:
	@echo "$(GREEN)Installing $(BINARY_NAME)...$(NC)"
	$(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) $(CMD_DIR)
	@echo "$(GREEN)Installed to $(GOPATH)/bin/$(BINARY_NAME)$(NC)"

## Show help
help:
	@echo "Wormhole - Zero-config tunnel tool"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build for current platform"
	@echo "  make build-all      # Build for all platforms"
	@echo "  make test           # Run tests"
	@echo "  make test-coverage  # Run tests with coverage report"
	@echo "  make docker-build   # Build Docker image"
