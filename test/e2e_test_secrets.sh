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
go build -o sget ./cmd/sget
tmp=$(mktemp -d)
cp cosign $tmp/
cp sget $tmp/

pushd $tmp

pass="$RANDOM"
export COSIGN_PASSWORD=$pass

BASE_TEST_REPO=${BASE_TEST_REPO:-us-central1-docker.pkg.dev/projectsigstore/cosign-ci}

# setup
./cosign generate-key-pair
img="${BASE_TEST_REPO}/test"
img2="${BASE_TEST_REPO}/test-2"
legacy_img="${BASE_TEST_REPO}/legacy-test"
for image in $img $img2 $legacy_img
do
    (crane delete $(./cosign triangulate $image)) || true
    crane cp busybox $image
done
img_copy="${img}/copy"
crane ls $img_copy | while read tag ; do crane delete "${img_copy}:${tag}" ; done
multiarch_img="${BASE_TEST_REPO}/multiarch-test"
crane ls $multiarch_img | while read tag ; do crane delete "${multiarch_img}:${tag}" ; done
crane cp gcr.io/distroless/base $multiarch_img

## sign/verify
./cosign sign -key cosign.key $img
./cosign verify -key cosign.pub $img

# copy
./cosign copy $img $img_copy
./cosign verify -key cosign.pub $img_copy

# sign recursively
./cosign sign -key cosign.key -r $multiarch_img
./cosign verify -key cosign.pub $multiarch_img # verify image index
for arch in "linux/amd64" "linux/arm64" "linux/s390x"
do
    # verify sigs on discrete images
    ./cosign verify -key cosign.pub "${multiarch_img}@$(crane digest --platform=$arch ${multiarch_img})"
done

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

## upload blob/sget
blobimg="${BASE_TEST_REPO}/blob"
crane ls ${blobimg} | while read tag ; do crane delete "${blobimg}:${tag}" ; done

# make a random blob
cat /dev/urandom | head -n 10 | base64 > randomblob

# upload-blob and sign it
dgst=$(./cosign upload-blob -f randomblob ${blobimg})
./cosign sign -key cosign.key ${dgst}
./cosign verify -key cosign.pub ${dgst} # For sanity

# sget w/ signature verification should work via tag or digest
./sget -key cosign.pub -o verified_randomblob_from_digest $dgst
./sget -key cosign.pub -o verified_randomblob_from_tag $blobimg

# sget w/o signature verification should only work for ref by digest
./sget -key cosign.pub -o randomblob_from_digest $dgst
if (./sget -o randomblob_from_tag $blobimg); then false; fi

# clean up a bit
crane delete $blobimg || true
crane delete $dgst || true

# Make sure they're the same
if ( ! cmp -s randomblob verified_randomblob_from_digest ); then false; fi
if ( ! cmp -s randomblob verified_randomblob_from_tag ); then false; fi
if ( ! cmp -s randomblob randomblob_from_digest ); then false; fi

# TODO: tlog

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
export COSIGN_REPOSITORY=${BASE_TEST_REPO}/subrepo
(crane delete $(./cosign triangulate $img)) || true
./cosign sign -key $kms $img
./cosign verify -key cosign.pub $img
unset COSIGN_REPOSITORY

# What else needs auth?
echo "SUCCESS"
