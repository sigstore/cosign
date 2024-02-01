#!/usr/bin/env bash
#
# Copyright 2024 The Sigstore Authors.
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

# This test was done for https://github.com/sigstore/cosign/pull/3464
# to verify that 'cosign verify' can work with the '--ca-roots'
# command-line option. It is a modified copy of e2e_tsa_mtls.sh.

set -exuo pipefail

## Requirements
# - cosign
# - crane
# - go

CERT_BASE="test/testdata"

export TIMESTAMP_SERVER_URL=https://freetsa.org/tsr
TIMESTAMP_CHAIN_FILE="timestamp-chain"
curl -s https://www.freetsa.org/files/cacert.pem > $TIMESTAMP_CHAIN_FILE
echo "TIMESTAMP_CHAIN_FILE: $(ls -l $TIMESTAMP_CHAIN_FILE)"
COSIGN_CLI=./cosign

# unlike e2e_tsa_mtls.sh, there is no option to pass an image as a command-line parameter.

# Upload an image to ttl.sh - commands from https://docs.sigstore.dev/cosign/keyless/
SRC_IMAGE=busybox
SRC_DIGEST=$(crane digest busybox)
for i in 01 02; do
	IMAGE_URI_TEMP=ttl.sh/$(uuidgen | head -c 8 | tr 'A-Z' 'a-z')
	crane cp $SRC_IMAGE@$SRC_DIGEST "${IMAGE_URI_TEMP}:3h"
	declare "IMG${i}=${IMAGE_URI_TEMP}@${SRC_DIGEST}"
done


echo "IMG01: $IMG01, IMG02: $IMG02, TIMESTAMP_SERVER_URL: $TIMESTAMP_SERVER_URL"

# use gencert to generate two CAs (for testing certificate bundle feature),
# keys and certificates
echo "generate CAs, keys and certificates with gencert"
passwd=$(uuidgen | head -c 32 | tr 'A-Z' 'a-z')
rm -f *.pem import-cosign.*
for i in 01 02; do
	go run test/gencert/main.go -output-suffix "$i" -intermediate
	COSIGN_PASSWORD="$passwd" $COSIGN_CLI import-key-pair --key ca-intermediate-key${i}.pem --output-key-prefix import-cosign${i}
	IMG="IMG${i}"
	cat ca-intermediate${i}.pem ca-root${i}.pem > certchain${i}.pem
	COSIGN_PASSWORD="$passwd" $COSIGN_CLI sign --timestamp-server-url "${TIMESTAMP_SERVER_URL}" \
		--upload=true --tlog-upload=false --key import-cosign${i}.key --certificate-chain certchain${i}.pem --cert cert${i}.pem "${!IMG}"
	# key is now longer needed
	rm -f key${i}.pem import-cosign${i}.*
done

# create a certificate bundle - concatenate both generated CA certificates
ls -l *.pem
cat ca-root01.pem ca-root02.pem > ca-roots.pem
cat ca-intermediate01.pem ca-intermediate02.pem > ca-intermediates.pem

echo "cosign verify:"
for i in 01 02; do
	IMG="IMG${i}"
	# first try with --certificate-chain parameter
	$COSIGN_CLI verify --insecure-ignore-tlog --insecure-ignore-sct --check-claims=true \
		--certificate-identity-regexp 'xyz@nosuchprovider.com' --certificate-oidc-issuer-regexp '.*' \
		--certificate-chain certchain${i}.pem --timestamp-certificate-chain $TIMESTAMP_CHAIN_FILE "${!IMG}"

	# then do the same but now with --ca-roots and --ca-intermediates parameters
	$COSIGN_CLI verify --insecure-ignore-tlog --insecure-ignore-sct --check-claims=true \
		--certificate-identity-regexp 'xyz@nosuchprovider.com' --certificate-oidc-issuer-regexp '.*' \
		--ca-roots ca-roots.pem --ca-intermediates ca-intermediates.pem --timestamp-certificate-chain $TIMESTAMP_CHAIN_FILE "${!IMG}"
done

# cleanup
rm -fr *.pem timestamp-chain
