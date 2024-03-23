# VARIABLES
#//////////////////////////////////////////////////////////////////////////////

### Binaries.
BINDIR  :=  $(CURDIR)/bin
BINNAME ?= paranoia
INSTALL_PATH ?= /usr/local/bin

# Git vars
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
CLI_VERSION ?= $(if $(shell git describe --tags),$(shell git describe --tags),"UnknownVersion")

# Go CLI options
PKG         := ./...
TESTS       := .
TESTFLAGS   := -race -v
LDFLAGS     := -w -s
GOFLAGS     :=
CGO_ENABLED ?= 0

# Project sources.
SRC := $(shell find . -type f -name '*.go' -print) go.mod go.sum

# TASKS
#//////////////////////////////////////////////////////////////////////////////

.PHONY: ensure-trivy-operator
ensure-trivy-operator:
	@echo "Ensuring trivy-operator is installed"
	@if ! kubectl get namespace trivy-system &> /dev/null; then \
		echo "trivy-operator is not installed"; \
		echo "Please install it following the instructions at https://github.com/aquasecurity/trivy-operator#installation"; \
		exit 1; \
	fi

.PHONY: all
all: build test

.PHONY: clean
clean:
	go clean

.PHONY: build
build: $(BINNAME)

$(BINNAME): $(SRC)
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o '$(BINNAME)' .

.PHONY: test
test:
	go clean -testcache && go test $(GOFLAGS) -run $(TESTS) $(PKG) $(TESTFLAGS)

.PHONY: install
install:
	go install $(GOFLAGS)