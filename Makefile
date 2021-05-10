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
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)

BUILDER=cosign-builder
PKG=github.com/sigstore/cosign/cmd/cosign/cli

.PHONY: all create-builder lint license-check vendor-validate test clean cosign cross

all: cosign

create-builder:
	docker buildx create --name $(BUILDER) --driver docker-container || true
	docker buildx inspect --bootstrap --builder $(BUILDER) || true

cosign: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) artifact

cosign-all: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) artifact-all

lint: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) lint

license-check: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) license-check

vendor-validate: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) vendor-validate

vendor-update: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) vendor-update

test: create-builder
	docker buildx bake --progress plain --builder $(BUILDER) test

clean:
	rm -rf cosign

.PHONY: ko
ko:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	CGO_ENABLED=0 GOFLAGS="-tags=pivkeydisabled -ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/cosign/cmd/cosign

.PHONY: ko-local
ko-local:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	CGO_ENABLED=0 GOFLAGS="-tags=pivkeydisabled -ldflags=-X=$(PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/cosign/cmd/cosign

.PHONY: sign-container
sign-container: ko
	cosign sign -key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_DOCKER_REPO}:$(GIT_HASH)
