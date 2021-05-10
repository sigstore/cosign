#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# syntax=docker/dockerfile:1.2
ARG GO_VERSION=1.16

FROM golang:${GO_VERSION}-alpine AS base
RUN apk add --no-cache ca-certificates gcc linux-headers musl-dev pcsc-lite-dev pkgconfig
WORKDIR /src

FROM golangci/golangci-lint:v1.39-alpine AS golangci-lint
FROM base AS lint
RUN --mount=type=bind,target=. \
  --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/root/.cache/golangci-lint \
  --mount=from=golangci-lint,source=/usr/bin/golangci-lint,target=/usr/bin/golangci-lint \
  golangci-lint run --timeout 10m0s ./...
