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

# This test checks that verify-blob will iterate over all entries and check for at least one valid entry before erroring out
# This is to prevent verify-blob from only checking the most recent entry, which could result
# in a "denial of service" type attack if someone signs a piece of software
# with their own certificate which doesn't chain up to Sigstore

set -ex

export COSIGN_EXPERIMENTAL=1
COSIGN_CLI=./cosign

echo "Creating a unique blob"
BLOB=verify-experimental-blob
date > $BLOB
cat $BLOB

echo "Sign the blob with cosign first and upload to rekor"
$COSIGN_CLI sign-blob --bundle blob.bundle --output-signature blob.sig $BLOB

echo "Verifying ..."
$COSIGN_CLI verify-blob --signature blob.sig --bundle blob.bundle $BLOB
echo "Verifying using cosign ENV variables..."
COSIGN_SIGNATURE=blob.sig COSIGN_BUNDLE=blob.bundle $COSIGN_CLI verify-blob $BLOB

# Now, sign the blob with a self-signed certificate and upload to rekor
SIG_FILE=verify-experimental-signature
PRIV_KEY=./test/testdata/test_blob_private_key
PUB_KEY=./test/testdata/test_blob_public_key
CERT_FILE=./test/testdata/test_blob_cert.pem

openssl dgst -sha256 -sign $PRIV_KEY -out $SIG_FILE $BLOB
openssl dgst -sha256 -verify $PUB_KEY -signature $SIG_FILE $BLOB

SHA256HASH=$(sha256sum $BLOB |  cut -f1 -d' ')

SIGNATURE=$(cat $SIG_FILE | base64)
echo "Signature: $SIGNATURE"

CERT=$(cat $CERT_FILE | base64)
echo "Cert: $CERT"

JSON_BODY_FILE=verify-experimental-blob-http-body.json
cat <<EOF > $JSON_BODY_FILE
{
    "apiVersion": "0.0.1",
    "spec": {
        "data": {
            "hash": {
                "algorithm": "sha256",
                "value": "$SHA256HASH"
            }
        },
        "signature": {
            "content": "$SIGNATURE",
            "publicKey": {
                "content": "$CERT"
            }
        }
    },
    "kind": "hashedrekord"
}
EOF

curl -X POST https://rekor.sigstore.dev/api/v1/log/entries -H 'Content-Type: application/json'  -d @$JSON_BODY_FILE

# Verifying should still work
echo "Verifying ..."
$COSIGN_CLI verify-blob --signature "$SIG_FILE" --cert "$CERT_FILE" --certificate-chain "$CERT_FILE" --insecure-ignore-sct "$BLOB"

echo "Verifying using cosign ENV variables ..."
COSIGN_SIGNATURE="$SIG_FILE" COSIGN_CERTIFICATE_CHAIN="$CERT_FILE" COSIGN_CERTIFICATE="$CERT_FILE" $COSIGN_CLI verify-blob --insecure-ignore-sct "$BLOB"
