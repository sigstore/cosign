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

go build -o cosign ./cmd/cosign
tmp=$(mktemp -d)
cp cosign $tmp/

pushd $tmp

pass="$RANDOM"

export COSIGN_PASSWORD=$pass
# setup
./cosign generate-key-pair
img="us-central1-docker.pkg.dev/projectsigstore/cosign-ci/test"
img2="us-central1-docker.pkg.dev/projectsigstore/cosign-ci/test-2"
legacy_img="us-central1-docker.pkg.dev/projectsigstore/cosign-ci/legacy-test"
img_copy="${img}/copy"
for image in $img $img2 $legacy_img
do
    (crane delete $(./cosign triangulate $image)) || true
    crane cp busybox $image
done
crane ls $img_copy | while read tag ; do crane delete $tag ; done


## sign/verify
./cosign sign -key cosign.key $img
./cosign verify -key cosign.pub $img

# copy
./cosign copy -source $img -destination $img_copy
./cosign verify -key cosign.pub $img_copy

## confirm use of OCI media type in signature image
crane manifest $(./cosign triangulate $img) | grep -q "application/vnd.oci.image.config.v1+json"

## sign/verify multiple images
./cosign sign -key cosign.key -a multiple=true $img $img2
./cosign verify -key cosign.pub -a multiple=true $img $img2

# annotations
if (./cosign verify -key cosign.pub -a foo=bar $img); then false; fi
./cosign sign -key cosign.key -a foo=bar $img
./cosign verify -key cosign.pub -a foo=bar $img

if (./cosign verify -key cosign.pub -a foo=bar -a bar=baz $img); then false; fi
./cosign sign -key cosign.key -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a bar=baz $img

# confirm the use of legacy (Docker) media types
COSIGN_DOCKER_MEDIA_TYPES=1 ./cosign sign -key cosign.key $legacy_img
./cosign verify -key cosign.pub $legacy_img
legacy_manifest=$(crane manifest $(./cosign triangulate $legacy_img))
echo $legacy_manifest | grep -q "application/vnd.docker.distribution.manifest.v2+json"
echo $legacy_manifest | grep -q "application/vnd.docker.container.image.v1+json"

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

## sign and verify multiple blobs
./cosign sign-blob -key cosign.key myblob myblob2 > sigs
./cosign verify-blob -key cosign.pub -signature <(head -n 1 sigs) myblob
./cosign verify-blob -key cosign.pub -signature <(tail -n 1 sigs) myblob2

## KMS!
kms="gcpkms://projects/projectsigstore/locations/global/keyRings/e2e-test/cryptoKeys/test"
(crane delete $(./cosign triangulate $img)) || true
./cosign generate-key-pair -kms $kms

if (./cosign verify -key cosign.pub $img); then false; fi
./cosign sign -key $kms $img
./cosign verify -key cosign.pub $img

if (./cosign verify -a foo=bar -key cosign.pub $img); then false; fi
./cosign sign -key $kms -a foo=bar $img
./cosign verify -key cosign.pub -a foo=bar $img

# store signatures in a different repo
export COSIGN_REPOSITORY=us-central1-docker.pkg.dev/projectsigstore/subrepo
(crane delete $(./cosign triangulate $img)) || true
./cosign sign -key $kms $img
./cosign verify -key cosign.pub $img
unset COSIGN_REPOSITORY

# TODO: tlog


# What else needs auth?
echo "SUCCESS"
