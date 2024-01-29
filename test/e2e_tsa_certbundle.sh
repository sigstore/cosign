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

# the certificates listed below are generated with the `gen-tsa-mtls-certs.sh` script.
TIMESTAMP_CACERT=$CERT_BASE/tsa-mtls-ca.crt
TIMESTAMP_CLIENT_CERT=$CERT_BASE/tsa-mtls-client.crt
TIMESTAMP_CLIENT_KEY=$CERT_BASE/tsa-mtls-client.key
TIMESTAMP_SERVER_CERT=$CERT_BASE/tsa-mtls-server.crt
TIMESTAMP_SERVER_KEY=$CERT_BASE/tsa-mtls-server.key
TIMESTAMP_SERVER_NAME="server.example.com"
TIMESTAMP_SERVER_URL=https://localhost:3000/api/v1/timestamp
TIMESTAMP_CHAIN_FILE="timestamp-chain"

set +e
COSIGN_CLI=./cosign
command -v timestamp-server >& /dev/null
exit_code=$?
set -e
if [[ $exit_code != 0 ]]; then
	rm -fr /tmp/timestamp-authority
	git clone https://github.com/sigstore/timestamp-authority /tmp/timestamp-authority
	pushd /tmp/timestamp-authority
	make
	export PATH="/tmp/timestamp-authority/bin:$PATH"
	popd
fi

timestamp-server serve --disable-ntp-monitoring --tls-host 0.0.0.0 --tls-port 3000 \
		--scheme https --tls-ca $TIMESTAMP_CACERT --tls-key $TIMESTAMP_SERVER_KEY \
		--tls-certificate $TIMESTAMP_SERVER_CERT &

sleep 1
curl -k -s --key test/testdata/tsa-mtls-client.key \
    --cert test/testdata/tsa-mtls-client.crt \
    --cacert test/testdata/tsa-mtls-ca.crt https://localhost:3000/api/v1/timestamp/certchain \
    > $TIMESTAMP_CHAIN_FILE
echo "DONE: $(ls -l $TIMESTAMP_CHAIN_FILE)"

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

rm -f *.pem import-cosign.* key.pem

# use gencert to generate two CAs (for testing certificate bundle feature),
# keys and certificates
echo "generate CAs, keys and certificates with gencert"

passwd=$(uuidgen | head -c 32 | tr 'A-Z' 'a-z')
rm -f *.pem import-cosign.*
for i in 01 02; do
	go run test/gencert/main.go && mv cacert.pem cacert${i}.pem && mv ca-key.pem ca-key${i}.pem && mv cert.pem cert${i}.pem && mv key.pem key${i}.pem
	COSIGN_PASSWORD="$passwd" $COSIGN_CLI import-key-pair --key key${i}.pem --output-key-prefix import-cosign${i}
	IMG="IMG${i}"
	COSIGN_PASSWORD="$passwd" $COSIGN_CLI sign --timestamp-server-url "${TIMESTAMP_SERVER_URL}" \
		--timestamp-client-cacert ${TIMESTAMP_CACERT} --timestamp-client-cert ${TIMESTAMP_CLIENT_CERT} \
		--timestamp-client-key ${TIMESTAMP_CLIENT_KEY} --timestamp-server-name ${TIMESTAMP_SERVER_NAME}\
		--upload=true --tlog-upload=false --key import-cosign${i}.key --certificate-chain cacert${i}.pem --cert cert${i}.pem "${!IMG}"
	# key is now longer needed
	rm -f key${i}.pem import-cosign${i}.*
done
# create a certificate bundle - concatenate both generated CA certificates
cat cacert01.pem cacert02.pem > ca-roots.pem

echo "cosign verify:"
for i in 01 02; do
	IMG="IMG${i}"
	$COSIGN_CLI verify --insecure-ignore-tlog --insecure-ignore-sct --check-claims=true \
		--certificate-identity-regexp 'xyz@nosuchprovider.com' --certificate-oidc-issuer-regexp '.*' \
		--ca-roots ca-roots.pem --timestamp-certificate-chain $TIMESTAMP_CHAIN_FILE "${!IMG}"
done

# cleanup
rm -fr ca-key*.pem ca-roots.pem cacert*.pem cert*.pem timestamp-chain /tmp/timestamp-authority
pkill -f 'timestamp-server'
