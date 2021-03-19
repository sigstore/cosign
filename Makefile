# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
BUILDDATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

LDFLAGS = "-X github.com/sigstore/cosign/cmd/cosign/cli.gitVersion=$(GIT_VERSION) \
             -X github.com/sigstore/cosign/cmd/cosign/cli.gitCommit=$(GIT_HASH) \
             -X github.com/sigstore/cosign/cmd/cosign/cli.gitTreeState=$(GIT_TREESTATE) \
             -X github.com/sigstore/cosign/cmd/cosign/cli.buildDate=$(BUILDDATE)"

.PHONY: all lint test clean

all: cosign

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

cosign: $(SRCS)
	go build -ldflags $(LDFLAGS) -o $@ ./cmd/cosign

lint:
	$(GOBIN)/golangci-lint run -v ./...

test:
	go test ./...

clean:
	rm -rf cosign
