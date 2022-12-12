#!/usr/bin/env bash
#
# Copyright 2022 The Sigstore Authors.
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

go build -o cosign ./cmd/cosign
go build -o sget ./cmd/sget
tmp=$(mktemp -d -t cosign-e2e-secrets.XXXX)
cp cosign $tmp/
cp sget $tmp/

pushd $tmp

pass="$RANDOM"
export COSIGN_PASSWORD=$pass

BASE_TEST_REPO=${BASE_TEST_REPO:-ttl.sh/cosign-ci}
TEST_INSTANCE_REPO="${BASE_TEST_REPO}/$(date +'%Y/%m/%d')/$RANDOM"

## KMS using env variables!
TEST_KMS=${TEST_KMS:-gcpkms://projects/projectsigstore/locations/global/keyRings/e2e-test/cryptoKeys/test}
(crane delete $(./cosign triangulate $img)) || true
COSIGN_KMS=$TEST_KMS ./cosign generate-key-pair
signing_key=$TEST_KMS

if (./cosign verify --key ${verification_key} $img); then false; fi
COSIGN_KEY=${signing_key} ./cosign sign $img
COSIGN_KEY=${verification_key} ./cosign verify $img

if (./cosign verify -a foo=bar --key ${verification_key} $img); then false; fi
COSIGN_KEY=${signing_key} ./cosign sign -a foo=bar $img
COSIGN_KEY=${verification_key} ./cosign verify -a foo=bar $img

# store signatures in a different repo
export COSIGN_REPOSITORY=${TEST_INSTANCE_REPO}/subbedrepo
(crane delete $(./cosign triangulate $img)) || true
COSIGN_KEY=${signing_key} ./cosign sign $img
COSIGN_KEY=${verification_key} ./cosign verify $img
unset COSIGN_REPOSITORY

# test stdin interaction for private key password
stdin_password=${COSIGN_PASSWORD}
unset COSIGN_PASSWORD
(crane delete $(./cosign triangulate $img)) || true
echo $stdin_password | ./cosign sign --key ${signing_key} --output-signature interactive.sig  $img
COSIGN_KEY=${verification_key} COSIGN_SIGNATURE=interactive.sig ./cosign verify $img
export COSIGN_PASSWORD=${stdin_password}

# What else needs auth?
echo "SUCCESS"
