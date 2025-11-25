#!/usr/bin/env bash
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

set -ex

echo "downloading sigstore/scaffolding repository"
SCAFFOLDING_DIR=$(mktemp -d)
git clone https://github.com/sigstore/scaffolding.git "$SCAFFOLDING_DIR"
SCAFFOLDING_SETUP_DIR="$SCAFFOLDING_DIR/actions/setup-sigstore-env"

echo "setting up sigstore test environment"
pushd "$SCAFFOLDING_SETUP_DIR"
source ./run-containers.sh
popd

cleanup() {
    echo "cleaning up sigstore test environment"
    pushd "$SCAFFOLDING_SETUP_DIR"
    stop_services
    popd
    docker rm -f registry registry-2 || true
}
trap cleanup EXIT

echo
echo "running tests"
go test -tags=e2e -v -race ./test/...

# Test on a private registry
echo "testing sign/verify/clean on private registry"
docker run -d -p 5000:5000 --restart always -e REGISTRY_STORAGE_DELETE_ENABLED=true --name registry registry:latest
export COSIGN_TEST_REPO=localhost:5000
go test -tags=e2e -v ./test/... -run TestSignVerifyClean

# Test with signature in separate registry
docker run -d -p 5001:5000 --restart always -e REGISTRY_STORAGE_DELETE_ENABLED=true --name registry-2 registry:latest
export COSIGN_REPOSITORY=localhost:5001/hello
go test -tags=e2e -v ./test/... -run TestSignVerifyWithRepoOverride

# Run the built container to make sure it doesn't crash
make ko-local
img="ko.local/cosign:$(git rev-parse HEAD)"
docker run $img version
