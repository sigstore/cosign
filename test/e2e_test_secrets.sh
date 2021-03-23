#!/bin/bash
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

if (./cosign verify -key cosign.pub -a foo=bar bar=baz $img); then false; fi
./cosign sign -key cosign.key -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a foo=bar -a bar=baz $img
./cosign verify -key cosign.pub -a bar=baz $img

# wrong keys
mkdir wrong && pushd wrong
../cosign generate-key-pair
if (../cosign verify -key cosign.pub $img); then false; fi
popd

echo "SUCCESS"

# TODO: kms
# TODO: tlog
# TODO: sign-blob
# What else needs auth?