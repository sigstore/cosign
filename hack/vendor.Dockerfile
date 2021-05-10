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
RUN apk add --no-cache ca-certificates gcc git linux-headers musl-dev pcsc-lite-dev pkgconfig
WORKDIR /src

FROM base AS vendored
RUN --mount=type=bind,target=.,rw \
  --mount=type=cache,target=/go/pkg/mod \
  go mod tidy && go mod download && \
  mkdir /out && cp go.mod go.sum /out

FROM scratch AS update
COPY --from=vendored /out /

FROM vendored AS validate
RUN --mount=type=bind,target=.,rw \
  git add -A && cp -rf /out/* .; \
  if [ -n "$(git status --porcelain -- go.mod go.sum)" ]; then \
    echo >&2 'ERROR: Vendor result differs. Please vendor your package with "docker buildx bake vendor-update"'; \
    git status --porcelain -- go.mod go.sum; \
    exit 1; \
  fi
