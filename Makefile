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

GOFILES ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

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
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64

LDFLAGS=-X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
        -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
        -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
        -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)

.PHONY: all lint test clean cosign cross
all: cosign

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: ## Check formatting of all go files
	@ $(MAKE) --no-print-directory log-$@
 	$(shell test -z "$(shell gofmt -l $(GOFILES) | tee /dev/stderr)")
 	$(shell test -z "$(shell goimports -l $(GOFILES) | tee /dev/stderr)")

.PHONY: fmt
fmt: ## Format all go files
	@ $(MAKE) --no-print-directory log-$@
	goimports -w $(GOFILES)

cosign: $(SRCS)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/cosign

cosign-pivkey-pkcs11key: $(SRCS)
	CGO_ENABLED=1 go build -trimpath -tags=pivkey,pkcs11key -ldflags "$(LDFLAGS)" -o cosign ./cmd/cosign

.PHONY: cosigned
cosigned: ## Build cosigned binary
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/cosign/webhook

.PHONY: sget
sget: ## Build sget binary
	go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/sget

.PHONY: cross
cross:
	$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	go build -trimpath -ldflags "$(LDFLAGS)" -o cosign-$(GOOS)-$(GOARCH) ./cmd/cosign; \
	shasum -a 256 cosign-$(GOOS)-$(GOARCH) > cosign-$(GOOS)-$(GOARCH).sha256 ))) \

#####################
# lint / test section
#####################

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.43.0 ;\

lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT_BIN) run -n

test:
	go test ./...

clean:
	rm -rf cosign
	rm -rf cosigned
	rm -rf sget
	rm -rf dist/

##########
# ko build
##########
.PHONY: ko
ko:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign

	# cosigned
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KO_DOCKER_REPO=${KO_PREFIX}/cosigned ko publish --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign/webhook

	# sget
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/sget

.PHONY: ko-local
ko-local:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/cosign/cmd/cosign

##################
# help
##################

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
include test/ci.mk

##########################
# Documentation generation
##########################

.PHONY: docgen
docgen:
	go run -tags pivkey,pkcs11key,cgo ./cmd/help/
