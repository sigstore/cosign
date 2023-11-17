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

# This test checks that verify-blob will iterate over all entries and check for at least one valid entry before erroring out
# This is to prevent verify-blob from only checking the most recent entry, which could result
# in a "denial of service" type attack if someone signs a piece of software
# with their own certificate which doesn't chain up to Sigstore

set -ex

COSIGN_CLI=./cosign
CERT_BASE="test/testdata"

# the certificates listed below are generated with the `gen-tsa-mtls-certs.sh` script.
TIMESTAMP_CACERT=$CERT_BASE/tsa-mtls-ca.crt
TIMESTAMP_CLIENT_CERT=$CERT_BASE/tsa-mtls-client.crt
TIMESTAMP_CLIENT_KEY=$CERT_BASE/tsa-mtls-client.key
TIMESTAMP_SERVER_CERT=$CERT_BASE/tsa-mtls-server.crt
TIMESTAMP_SERVER_KEY=$CERT_BASE/tsa-mtls-server.key
TIMESTAMP_SERVER_NAME="server.example.com"
TIMESTAMP_SERVER_URL=https://localhost:3000/api/v1/timestamp
TIMESTAMP_CHAIN_FILE="timestamp-chain.pem"

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
echo "Creating a unique blob"
BLOB=verify-experimental-blob
date > $BLOB
cat $BLOB

rm -f ca-key.pem cacert.pem cert.pem key.pem import-cosign.*
# use gencert to generate CA, keys and certificates
echo "generate keys and certificates with gencert"

passwd=$(uuidgen | head -c 32 | tr 'A-Z' 'a-z')
go run test/gencert/main.go \
    && COSIGN_PASSWORD="$passwd" $COSIGN_CLI import-key-pair --key key.pem

echo "Sign the blob with cosign first and upload to rekor"
COSIGN_PASSWORD="$passwd" $COSIGN_CLI sign-blob --yes \
    --key import-cosign.key \
	--timestamp-server-url "${TIMESTAMP_SERVER_URL}" \
	--timestamp-client-cacert ${TIMESTAMP_CACERT} --timestamp-client-cert ${TIMESTAMP_CLIENT_CERT} \
	--timestamp-client-key ${TIMESTAMP_CLIENT_KEY} --timestamp-server-name ${TIMESTAMP_SERVER_NAME} \
    --rfc3161-timestamp=timestamp.txt --tlog-upload=false \
    --bundle cosign.bundle $BLOB

echo "Verifying ..."
$COSIGN_CLI verify-blob --bundle cosign.bundle \
    --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
    --rfc3161-timestamp=timestamp.txt --timestamp-certificate-chain=$TIMESTAMP_CHAIN_FILE \
    --insecure-ignore-tlog=true --key import-cosign.pub $BLOB

$COSIGN_CLI verify-blob --bundle cosign.bundle \
    --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
    --rfc3161-timestamp=timestamp.txt --timestamp-certificate-chain=$TIMESTAMP_CHAIN_FILE \
    --private-infrastructure --key import-cosign.pub $BLOB

# cleanup
rm -fr blob.sig ca-key.pem cacert.pem cert.pem cosign.bundle import-cosign.key \
    import-cosign.pub key.pem timestamp.txt timestamp-chain.pem \
    /tmp/timestamp-authority verify-experimental-blob
pkill -f 'timestamp-server'
