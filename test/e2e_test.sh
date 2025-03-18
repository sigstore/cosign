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

docker_compose="docker compose"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose"
fi

echo "setting up OIDC provider"
pushd ./test/fakeoidc

# in CI ko-build/setup-ko, will set this var to ghcr.io
KO_DOCKER_REPO="${KO_DOCKER_REPO:=ko.local}"
ko build --local --base-import-paths
docker start fakeoidc || docker run -d --rm -p 8080:8080 --hostname $(hostname) --name fakeoidc $KO_DOCKER_REPO/fakeoidc
cleanup_oidc() {
    echo "cleaning up oidc"
    docker stop fakeoidc
}
trap cleanup_oidc EXIT
export OIDC_URL="http://$(hostname):8080"
cat <<EOF > /tmp/fulcio-config.json
{
  "OIDCIssuers": {
    "$OIDC_URL": {
      "IssuerURL": "$OIDC_URL",
      "ClientID": "sigstore",
      "Type": "email"
    }
  }
}
EOF
popd

pushd $HOME

# fetch from https://github.com/ramonpetgrave64/scaffolding/blob/portable-testing/actions/portable_testing/Makefile
echo "downloading scaffoding pertable sigstore Makefile"
wget -q https://raw.github.com/ramonpetgrave64/scaffolding/portable-testing/actions/portable_testing/Makefile

echo "starting services"
export FULCIO_METRICS_PORT=2113
export FULCIO_CONFIG=/tmp/fulcio-config.json
export CHECKOUT_DIR=$HOME
make
cleanup_services() {
    echo "cleaning up"
    cleanup_oidc
    pushd $HOME
    make down clean
    popd
}
trap cleanup_services EXIT

echo "atach fakeoidc"
docker network disconnect fulcio_default fakeoidc || true
docker network connect --alias $(hostname) fulcio_default fakeoidc

echo
echo "running tests"

popd
go test -tags=e2e -v -race ./test/...

# Test on a private registry
echo "testing sign/verify/clean on private registry"
cleanup() {
    cleanup_services
    docker rm -f registry
}
trap cleanup EXIT
docker run -d -p 5000:5000 --restart always -e REGISTRY_STORAGE_DELETE_ENABLED=true --name registry registry:latest
export COSIGN_TEST_REPO=localhost:5000
go test -tags=e2e -v ./test/... -run TestSignVerifyClean

# Run the built container to make sure it doesn't crash
make ko-local
img="ko.local/cosign:$(git rev-parse HEAD)"
docker run $img version
