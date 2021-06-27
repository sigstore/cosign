#!/bin/bash
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

echo "copying rekor repo"
pushd $HOME
git clone https://github.com/sigstore/rekor.git
cd rekor

echo "starting services"
docker-compose up -d

count=0

echo -n "waiting up to 60 sec for system to start"
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

echo
echo "running tests"

popd
go build -o cosign ./cmd/cosign
go test -tags=e2e -race ./...

# Run the built container to make sure it doesn't crash
make ko-local
img="ko.local:$(git rev-parse HEAD)"
docker run $img version

echo "cleanup"
cd $HOME/rekor
docker-compose down
