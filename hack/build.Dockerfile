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
ARG PACKAGE=github.com/sigstore/cosign/cmd/cosign

FROM --platform=$BUILDPLATFORM crazymax/goreleaser-xx:latest AS goreleaser-xx
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS base
RUN apk add --no-cache ca-certificates gcc file git linux-headers musl-dev pcsc-lite-dev pkgconfig tar
COPY --from=goreleaser-xx / /
WORKDIR /src

FROM base AS build
ARG TARGETPLATFORM
ARG GIT_REF
ARG PACKAGE
RUN --mount=type=bind,target=/src,rw \
  --mount=type=cache,target=/root/.cache/go-build \
  --mount=target=/go/pkg/mod,type=cache \
  goreleaser-xx --debug \
    --name "cosign" \
    --dist "/out" \
    --artifact-type="bin" \
    --hooks="go mod tidy" \
    --hooks="go mod download" \
    --main "./cmd/cosign" \
    --ldflags="-s -w -X ${PACKAGE}/cli.version={{.Version}} -X ${PACKAGE}/cli.commit={{.Commit}} -X ${PACKAGE}/cli.buildDate={{.Date}}"

FROM scratch AS artifacts
COPY --from=build /out /
