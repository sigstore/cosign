#!/usr/bin/env bash

# Copyright 2024 The Sigstore Authors.
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

set -o errexit
set -o nounset
set -o pipefail

# Test pkcs11 token signing
# using a fork of https://github.com/vegardit/docker-softhsm2-pkcs11-proxy that stopped to build 5 months ago
CONTAINER_ID=$(docker run -dit --name softhsm -v $(pwd):/root/cosign -p 2345:2345 ghcr.io/cpanato/softhsm2-pkcs11-proxy:latest@sha256:2614345f73f9432d85365f0ac450c4bf0abac51b205b54241a94f9cf9e671772)

docker exec -i $CONTAINER_ID /bin/bash << 'EOF'

# to install the latest go that is not available in the alpine repository
echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
apk update

# add make pcsc-lite-libs go command
apk add make build-base

apk add go@edge

cd /root/cosign

softhsm2-util --init-token --free --label "My Token" --pin 1234 --so-pin 1234
go test -v -cover -coverprofile=./cover.out -tags=softhsm,pkcs11key -coverpkg github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key test/pkcs11_test.go

EOF

cleanup_pkcs11() {
    docker rm -f $CONTAINER_ID
}

trap cleanup_pkcs11 EXIT
