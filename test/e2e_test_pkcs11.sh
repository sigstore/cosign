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

set -ex

# Test pkcs11 token signing
CONTAINER_ID=$(docker run -dit --name softhsm -v $(pwd):/root/cosign -p 2345:2345 vegardit/softhsm2-pkcs11-proxy@sha256:557a65d2a14e3986f2389d36ddce75609cbd8fb7ee6cf08a78adcc8236c2a80e)

docker exec -i $CONTAINER_ID /bin/bash << 'EOF'

apk update

# add make pcsc-lite-libs go command
apk add make build-base go

cd /root/cosign

softhsm2-util --init-token --free --label "My Token" --pin 1234 --so-pin 1234
go test -v -cover -coverprofile=./cover.out -tags=softhsm,pkcs11key -coverpkg github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key test/pkcs11_test.go

EOF

cleanup_pkcs11() {
    docker rm -f $CONTAINER_ID
}

trap cleanup_pkcs11 EXIT
