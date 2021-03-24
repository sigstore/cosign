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


## KMS!
kms="gcpkms://projects/projectsigstore/locations/global/keyRings/e2e-test/cryptoKeys/test"
(crane delete $(./cosign triangulate $img)) || true
./cosign generate-key-pair -kms $kms

if (./cosign verify -key cosign.pub $img); then false; fi
./cosign sign -kms $kms $img
./cosign verify -key cosign.pub $img

if (./cosign verify -a foo=bar -key cosign.pub $img); then false; fi
./cosign sign -kms $kms -a foo=bar $img
./cosign verify -key cosign.pub -a foo=bar $img

# TODO: tlog


# What else needs auth?
echo "SUCCESS"
