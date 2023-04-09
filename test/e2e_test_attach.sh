#!/usr/bin/env bash
#
# Copyright 2023 The Sigstore Authors.
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
tmp=$(mktemp -d -t cosign-e2e-attach.XXXX)
cp cosign $tmp/

#copying key, cert, certchain and rootcert in temp folder
cp ./test/testdata/test_attach_private_key $tmp/private_key
cp ./test/testdata/test_attach_leafcert.pem $tmp/leafcert.pem
cp ./test/testdata/test_attach_certchain.pem $tmp/certchain.pem
cp ./test/testdata/test_attach_rootcert.pem $tmp/rootcert.pem

pushd $tmp

pass="$RANDOM"
export COSIGN_PASSWORD=$pass

SRC_IMAGE=busybox
SRC_DIGEST=$(crane digest busybox)
IMAGE_URI=ttl.sh/cosign-ci/$(uuidgen | head -c 8 | tr 'A-Z' 'a-z')
crane cp $SRC_IMAGE@$SRC_DIGEST $IMAGE_URI:1h
IMAGE_URI_DIGEST=$IMAGE_URI@$SRC_DIGEST


# `initialize`
./cosign initialize

## Generate
./cosign generate $IMAGE_URI_DIGEST > payload.json

## Sign with Leafcert Private Key
openssl dgst -sha256 -sign ./private_key -out payload.sig payload.json
cat payload.sig | base64 > payloadbase64.sig


SIGNATURE=$(cat payloadbase64.sig | base64)
echo "Signature: $SIGNATURE"

PAYLOAD=$(cat payload.json)
echo "Payload: $PAYLOAD"



## Attach Signature, payload, cert and cert-chain
./cosign attach signature --signature ./payloadbase64.sig --payload ./payload.json --cert ./leafcert.pem --cert-chain ./certchain.pem $IMAGE_URI_DIGEST


## confirm manifest conatins annotation for cert and cert chain
crane manifest $(./cosign triangulate $IMAGE_URI_DIGEST) | grep -q "application/vnd.oci.image.config.v1+json"
crane manifest $(./cosign triangulate $IMAGE_URI_DIGEST) | grep -q "dev.sigstore.cosign/certificate"
crane manifest $(./cosign triangulate $IMAGE_URI_DIGEST) | grep -q "dev.sigstore.cosign/chain"

## Verify Signature, payload, cert and cert-chain using SIGSTORE_ROOT_FILE

export SIGSTORE_ROOT_FILE=./rootcert.pem
./cosign verify $IMAGE_URI_DIGEST --insecure-ignore-sct --insecure-skip-tlog-verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*'


# clean up a bit
for image in $IMAGE_URI_DIGEST
do
    (crane delete $(./cosign triangulate $IMAGE_URI_DIGEST)) || true
done
crane delete $IMAGE_URI_DIGEST || true


# completed
echo "SUCCESS"
