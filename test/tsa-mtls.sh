#!/bin/bash
set -euo pipefail

## Requirements
# - cosign
# - crane
# - go

which cosign

CERT_BASE="testdata"

TIMESTAMP_CACERT=$CERT_BASE/tsa-mtls-cacert.pem
TIMESTAMP_CLIENT_CERT=$CERT_BASE/tsa-mtls-client.pem
TIMESTAMP_CLIENT_KEY=$CERT_BASE/tsa-mtls-client-key.pem
TIMESTAMP_SERVER_CERT=$CERT_BASE/tsa-mtls-server.pem
TIMESTAMP_SERVER_KEY=$CERT_BASE/tsa-mtls-server-key.pem
TIMESTAMP_SERVER_NAME="server.example.com"
TIMESTAMP_SERVER_URL=https://localhost:3000/api/v1/timestamp

rm -fr /tmp/timestamp-authority
git clone https://github.com/sigstore/timestamp-authority /tmp/timestamp-authority
pushd /tmp/timestamp-authority
make
popd
/tmp/timestamp-authority/bin/timestamp-server serve --disable-ntp-monitoring --tls-host 0.0.0.0 --tls-port 3000 \
	--scheme https --tls-ca $TIMESTAMP_CACERT --tls-key $TIMESTAMP_SERVER_KEY --tls-certificate $TIMESTAMP_SERVER_CERT &
export PATH="/tmp/timestampserver:$PATH"

IMG=${IMAGE_URI_DIGEST:-}
if [[ "$#" -ge 1 ]]; then
	IMG=$1
elif [[ -z "${IMG}" ]]; then
	# Upload an image to ttl.sh - commands from https://docs.sigstore.dev/cosign/keyless/
	SRC_IMAGE=busybox
	SRC_DIGEST=$(crane digest busybox)
	IMAGE_URI=ttl.sh/$(uuidgen | head -c 8 | tr 'A-Z' 'a-z')
	crane cp $SRC_IMAGE@$SRC_DIGEST $IMAGE_URI:3h
	IMG=$IMAGE_URI@$SRC_DIGEST
fi

echo "IMG (IMAGE_URI_DIGEST): $IMG, TIMESTAMP_SERVER_URL: $TIMESTAMP_SERVER_URL"

GOBIN=/tmp GOPROXY=https://proxy.golang.org,direct go install -v github.com/dmitris/gencert@latest

rm -f *.pem import-cosign.* key.pem


# use gencert to generate CA, keys and certificates
echo "generate keys and certificates with gencert"

passwd=$(uuidgen | head -c 32 | tr 'A-Z' 'a-z')
rm -f *.pem import-cosign.* && /tmp/gencert && COSIGN_PASSWORD="$passwd" cosign import-key-pair --key key.pem

COSIGN_PASSWORD="$passwd" cosign sign --timestamp-server-url "${TIMESTAMP_SERVER_URL}" \
	--timestamp-client-cacert ${TIMESTAMP_CACERT} --timestamp-client-cert ${TIMESTAMP_CLIENT_CERT} \
	--timestamp-client-key ${TIMESTAMP_CLIENT_KEY} --timestamp-server-name ${TIMESTAMP_SERVER_NAME}\
	--upload=true --tlog-upload=false --key import-cosign.key --certificate-chain cacert.pem --cert cert.pem $IMG

# key is now longer needed
rm -f key.pem import-cosign.*

echo "cosign verify:"
cosign verify --insecure-ignore-tlog --insecure-ignore-sct --check-claims=true \
	--certificate-identity-regexp 'xyz@nosuchprovider.com' --certificate-oidc-issuer-regexp '.*' \
	--certificate-chain cacert.pem $IMG

# cleanup
rm -fr ca-key.pem cacert.pem cert.pem /tmp/timestamp-authority
pkill timestamp-server