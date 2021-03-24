#!/bin/bash
# Copyright 2021 The Rekor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

go build -o cosign ./cmd/cosign
tmp=$(mktemp -d)
cp cosign $tmp/

pushd $tmp

pass="$RANDOM"

export COSIGN_PASSWORD=$pass
# setup
./cosign generate-key-pair
img="us-central1-docker.pkg.dev/projectsigstore/cosign-ci/test"
(crane delete $(./cosign triangulate $img)) || true
crane cp busybox $img

## sign/verify
./cosign sign -key cosign.key $img
./cosign verify -key cosign.pub $img

# annotations
if (./cosign verify -key cosign.pub -a foo=bar $img); then false; fi
./cosign sign -key cosign.key -a foo=bar $img
./cosign verify -key cosign.pub -a foo=bar $img

if (./cosign verify -key cosign.pub -a foo=bar -a bar=baz $img); then false; fi
./cosign sign -key cosign.key -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a bar=baz $img

# wrong keys
mkdir wrong && pushd wrong
../cosign generate-key-pair
if (../cosign verify -key cosign.pub $img); then false; fi
popd

## sign-blob
echo "myblob" > myblob
echo "myblob2" > myblob2
./cosign sign-blob -key cosign.key myblob > myblob.sig
./cosign sign-blob -key cosign.key myblob2 > myblob2.sig

./cosign verify-blob -key cosign.pub -signature myblob.sig myblob
if (./cosign verify-blob -key cosign.pub -signature myblob.sig myblob2); then false; fi

if (./cosign verify-blob -key cosign.pub -signature myblob2.sig myblob); then false; fi
./cosign verify-blob -key cosign.pub -signature myblob2.sig myblob2


# TODO: kms
# TODO: tlog


# What else needs auth?
echo "SUCCESS"
