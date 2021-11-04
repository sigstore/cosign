#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Set version variables for LDFLAGS
PROJECT_ID ?= projectsigstore
RUNTIME_IMAGE ?= gcr.io/distroless/static
GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

PKG=github.com/sigstore/cosign/cmd/cosign/cli/options

LDFLAGS="-X $(PKG).GitVersion=$(GIT_VERSION) -X $(PKG).gitCommit=$(GIT_HASH) -X $(PKG).gitTreeState=$(GIT_TREESTATE) -X $(PKG).buildDate=$(BUILD_DATE)"

.PHONY: all lint test clean cosign cross

all: cosign

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

cosign: $(SRCS)
	CGO_ENABLED=0 go build -trimpath -ldflags $(LDFLAGS) -o $@ ./cmd/cosign

cosign-pivkey: $(SRCS)
	CGO_ENABLED=1 go build -trimpath -tags=pivkey -ldflags $(LDFLAGS) -o cosign ./cmd/cosign

cosign-pkcs11key: $(SRCS)
	CGO_ENABLED=1 go build -trimpath -tags=pkcs11key -ldflags $(LDFLAGS) -o cosign ./cmd/cosign

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint
golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.42.0 ;\

lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT_BIN) run -n


PLATFORMS=darwin linux windows
ARCHITECTURES=amd64

cross:
	$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	go build -trimpath -ldflags $(LDFLAGS) -o cosign-$(GOOS)-$(GOARCH) ./cmd/cosign; \
	shasum -a 256 cosign-$(GOOS)-$(GOARCH) > cosign-$(GOOS)-$(GOARCH).sha256 ))) \

test:
	go test ./...

clean:
	rm -rf cosign

.PHONY: ko
ko:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	KO_DOCKER_REPO=${KO_PREFIX}/cosign CGO_ENABLED=0 GOFLAGS="-ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign

	# cosigned
	KO_DOCKER_REPO=${KO_PREFIX}/cosigned CGO_ENABLED=0 GOFLAGS="-ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign/webhook

	# sget
	KO_DOCKER_REPO=${KO_PREFIX}/sget CGO_ENABLED=0 GOFLAGS="-ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/sget

.PHONY: ko-local
ko-local:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	KO_DOCKER_REPO=${KO_PREFIX}/cosign CGO_ENABLED=0 GOFLAGS="-ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/cosign/cmd/cosign

.PHONY: sign-container
sign-container: ko
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosign:$(GIT_HASH)

.PHONY: sign-cosigned
sign-cosigned:
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/cosigned:$(GIT_HASH)

.PHONY: sign-sget
sign-sget:
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/sget:$(GIT_HASH)

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS=$(LDFLAGS) goreleaser release

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS=$(LDFLAGS) goreleaser release --skip-sign --skip-publish --snapshot --rm-dist

.PHONY: cosigned
cosigned: lint ## Build cosigned binary
	CGO_ENABLED=0 go build -trimpath -ldflags $(LDFLAGS) -o $@ ./cmd/cosign/webhook

.PHONY: sget
sget: ## Build sget binary
	go build -trimpath -o $@ ./cmd/sget
