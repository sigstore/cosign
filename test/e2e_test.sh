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

pushd $HOME

echo "downloading service repos"
for repo in rekor fulcio; do
    if [[ ! -d $repo ]]; then
        git clone https://github.com/sigstore/${repo}.git
    else
        pushd $repo
        git pull
        popd
    fi
done

echo "starting services"
export FULCIO_METRICS_PORT=2113
for repo in rekor fulcio; do
    pushd $repo
    docker-compose up -d
    echo -n "waiting up to 60 sec for system to start"
    count=0
    until [ $(docker-compose ps | grep -c "(healthy)") == 3 ];
    do
        if [ $count -eq 6 ]; then
           echo "! timeout reached"
           exit 1
        else
           echo -n "."
           sleep 10
           let 'count+=1'
        fi
    done
    popd
done
cleanup_services() {
    echo "cleaning up"
    for repo in rekor fulcio; do
        pushd $HOME/$repo
        docker-compose down
        popd
    done
}
trap cleanup_services EXIT

curl http://127.0.0.1:3000/api/v1/log/publicKey > rekor.pub
export SIGSTORE_REKOR_PUBLIC_KEY=$(pwd)/rekor.pub

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
