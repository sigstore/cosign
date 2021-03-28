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

PKG=github.com/sigstore/cosign/cmd/cosign/cli

LDFLAGS="-X $(PKG).gitVersion=$(GIT_VERSION) -X $(PKG).gitCommit=$(GIT_HASH) -X $(PKG).gitTreeState=$(GIT_TREESTATE)"

.PHONY: all lint test clean cosign cross

all: cosign

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

cosign: $(SRCS)
	CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o $@ ./cmd/cosign

GOLANGCI_LINT = $(shell pwd)/bin/golangci-lint
golangci-lint:
	rm -f $(GOLANGCI_LINT) || :
	set -e ;\
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell dirname $(GOLANGCI_LINT)) v1.36.0 ;\

lint: golangci-lint ## Runs golangci-lint linter
	$(GOLANGCI_LINT) run  -n


PLATFORMS=darwin linux
ARCHITECTURES=amd64

cross:
	$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	go build -ldflags $(LDFLAGS) -o cosign-$(GOOS)-$(GOARCH) ./cmd/cosign)))
	shasum -a 256 cosign-* > cosign.sha2556

test:
	go test ./...

clean:
	rm -rf cosign

.PHONY: ko
ko:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	GOFLAGS="-ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign

.PHONY: sign-container
sign-container: ko
	cosign sign -key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_DOCKER_REPO}:$(GIT_HASH)