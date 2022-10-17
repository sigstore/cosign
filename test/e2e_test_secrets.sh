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

go build -o cosign ./cmd/cosign
go build -o sget ./cmd/sget
tmp=$(mktemp -d -t cosign-e2e-secrets.XXXX)
cp cosign $tmp/
cp sget $tmp/

pushd $tmp

pass="$RANDOM"
export COSIGN_PASSWORD=$pass

BASE_TEST_REPO=${BASE_TEST_REPO:-us-central1-docker.pkg.dev/projectsigstore/cosign-ci}
TEST_INSTANCE_REPO="${BASE_TEST_REPO}/$(date +'%Y/%m/%d')/$RANDOM"

# setup
./cosign generate-key-pair
signing_key=cosign.key
verification_key=cosign.pub
img="${TEST_INSTANCE_REPO}/test"
img2="${TEST_INSTANCE_REPO}/test-2"
legacy_img="${TEST_INSTANCE_REPO}/legacy-test"
for image in $img $img2 $legacy_img
do
    (crane delete $(./cosign triangulate $image)) || true
    crane cp busybox $image
done
img_copy="${img}/copy"
crane ls $img_copy | while read tag ; do crane delete "${img_copy}:${tag}" ; done
multiarch_img="${TEST_INSTANCE_REPO}/multiarch-test"
crane ls $multiarch_img | while read tag ; do crane delete "${multiarch_img}:${tag}" ; done
crane cp ghcr.io/distroless/alpine-base $multiarch_img

# `initialize`
./cosign initialize

## Generate (also test output redirection
./cosign generate $img > payload1
./cosign generate --output-file=payload2 $img
diff payload1 payload2

## sign/verify
./cosign sign --key ${signing_key} $img
./cosign verify --key ${verification_key} $img

# copy
./cosign copy $img $img_copy
./cosign verify --key ${verification_key} $img_copy

# sign recursively
./cosign sign --key ${signing_key} -r $multiarch_img
./cosign verify --key ${verification_key} $multiarch_img # verify image index
for arch in "linux/amd64" "linux/arm64" "linux/s390x"
do
    # verify sigs on discrete images
    ./cosign verify --key ${verification_key} "${multiarch_img}@$(crane digest --platform=$arch ${multiarch_img})"
done

## confirm use of OCI media type in signature image
crane manifest $(./cosign triangulate $img) | grep -q "application/vnd.oci.image.config.v1+json"

## sign/verify multiple images
./cosign sign --key ${signing_key} -a multiple=true $img $img2
./cosign verify --key ${verification_key} -a multiple=true $img $img2

# annotations
if (./cosign verify --key ${verification_key} -a foo=bar $img); then false; fi
./cosign sign --key ${signing_key} -a foo=bar $img
./cosign verify --key ${verification_key} -a foo=bar $img

if (./cosign verify --key ${verification_key} -a foo=bar -a bar=baz $img); then false; fi
./cosign sign --key ${signing_key} -a foo=bar -a bar=baz $img
./cosign verify --key ${verification_key} -a foo=bar -a bar=baz $img
./cosign verify --key ${verification_key} -a bar=baz $img

# confirm the use of legacy (Docker) media types
COSIGN_DOCKER_MEDIA_TYPES=1 ./cosign sign --key ${signing_key} $legacy_img
./cosign verify --key ${verification_key} $legacy_img
legacy_manifest=$(crane manifest $(./cosign triangulate $legacy_img))
echo $legacy_manifest | grep -q "application/vnd.docker.distribution.manifest.v2+json"
echo $legacy_manifest | grep -q "application/vnd.docker.container.image.v1+json"

# wrong keys
mkdir wrong && pushd wrong
../cosign generate-key-pair
if (../cosign verify --key ${verification_key} $img); then false; fi
popd

## sign-blob
echo "myblob" > myblob
echo "myblob2" > myblob2
./cosign sign-blob --key ${signing_key} myblob > myblob.sig
./cosign sign-blob --key ${signing_key} myblob2 > myblob2.sig

./cosign verify-blob --key ${verification_key} --signature myblob.sig myblob
# expected to fail because signature mismatch
if (./cosign verify-blob --key ${verification_key} --signature myblob.sig myblob2); then false; fi

# expected to fail because signature mismatch
if (./cosign verify-blob --key ${verification_key} --signature myblob2.sig myblob); then false; fi
./cosign verify-blob --key ${verification_key} --signature myblob2.sig myblob2

./cosign sign-blob --key ${signing_key} --bundle bundle.sig myblob
# passes when local bundle only contains the key and signature
./cosign verify-blob --key ${verification_key} --bundle bundle.sig myblob

## sign and verify multiple blobs
./cosign sign-blob --key ${signing_key} myblob myblob2 > sigs
head -n 1 sigs > car.sig
tail -n 1 sigs > cdr.sig
./cosign verify-blob --key ${verification_key} --signature car.sig myblob
./cosign verify-blob --key ${verification_key} --signature cdr.sig myblob2

## upload blob/sget
blobimg="${TEST_INSTANCE_REPO}/blob"
crane ls ${blobimg} | while read tag ; do crane delete "${blobimg}:${tag}" ; done

# make a random blob
cat /dev/urandom | head -n 10 | base64 > randomblob

# upload blob and sign it
dgst=$(./cosign upload blob -f randomblob ${blobimg})
./cosign sign --key ${signing_key} ${dgst}
./cosign verify --key ${verification_key} ${dgst} # For sanity

# sget w/ signature verification should work via tag or digest
./sget --key ${verification_key} -o verified_randomblob_from_digest $dgst
./sget --key ${verification_key} -o verified_randomblob_from_tag $blobimg

# sget w/o signature verification should only work for ref by digest
./sget --key ${verification_key} -o randomblob_from_digest $dgst
if (./sget -o randomblob_from_tag $blobimg); then false; fi

# clean up a bit
crane delete $blobimg || true
crane delete $dgst || true

# Make sure they're the same
if ( ! cmp -s randomblob verified_randomblob_from_digest ); then false; fi
if ( ! cmp -s randomblob verified_randomblob_from_tag ); then false; fi
if ( ! cmp -s randomblob randomblob_from_digest ); then false; fi

# TODO: tlog

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
