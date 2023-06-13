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
tmp=$(mktemp -d -t cosign-e2e-secrets.XXXX)
cp cosign $tmp/

pushd $tmp

pass="$RANDOM"
export COSIGN_PASSWORD=$pass
# Skip confirmation for signing
export COSIGN_YES=true

BASE_TEST_REPO=${BASE_TEST_REPO:-ttl.sh/cosign-ci}
TEST_INSTANCE_REPO="${BASE_TEST_REPO}/$(date +'%Y/%m/%d')/$RANDOM"

# setup
./cosign generate-key-pair
signing_key=cosign.key
verification_key=cosign.pub
img="${TEST_INSTANCE_REPO}/test"
img2="${TEST_INSTANCE_REPO}/test-2"
img3="${TEST_INSTANCE_REPO}/test-3"
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

## Generate (also test output redirection)
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

# sign/attest an image that doesn't exist (yet) in the registry
# This digest was generated with the following command and
# does not exist anywhere AFAIK:
#   head -10 /dev/urandom | sha256sum | cut -d' ' -f 1
# We don't just run this here because the macos leg doesn't
# have sha256sum
./cosign sign --key ${signing_key} "$img3@sha256:17b14220441083f55dfa21e1deb3720457d3c2d571219801d629b43c53b99627"
PREDICATE_FILE=$(mktemp)
cat > "${PREDICATE_FILE}" <<EOF
{
  "foo": "bar"
}
EOF
./cosign attest --key ${signing_key} --type custom --predicate "${PREDICATE_FILE}" "$img3@sha256:17b14220441083f55dfa21e1deb3720457d3c2d571219801d629b43c53b99627"

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

## upload blob
blobimg="${TEST_INSTANCE_REPO}/blob"
crane ls ${blobimg} | while read tag ; do crane delete "${blobimg}:${tag}" ; done

# make a random blob
cat /dev/urandom | head -n 10 | base64 > randomblob

# upload blob and sign it
dgst=$(./cosign upload blob -f randomblob ${blobimg})
./cosign sign --key ${signing_key} ${dgst}
./cosign verify --key ${verification_key} ${dgst} # For sanity

# clean up a bit
crane delete $blobimg || true
crane delete $dgst || true

# upload blob and sign it
cat /dev/urandom | head -n 10 | base64 > randomblob
dgst=$(./cosign upload blob -f randomblob ${blobimg})
./cosign sign --key ${signing_key} --tlog-upload=false ${dgst}
./cosign verify --key ${verification_key} --insecure-ignore-tlog=true ${dgst} # For sanity

# clean up a bit
crane delete $blobimg || true
crane delete $dgst || true

# What else needs auth?
echo "SUCCESS"
