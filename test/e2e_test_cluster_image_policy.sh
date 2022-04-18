#!/usr/bin/env bash
#
# Copyright 2022 The Sigstore Authors.
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

if [[ -z "${OIDC_TOKEN}" ]]; then
  if [[ -z "${TOKEN_ISSUER}" ]]; then
    echo "Must specify either env variable OIDC_TOKEN or TOKEN_ISSUER"
    exit 1
  else
    export OIDC_TOKEN=`curl -s ${ISSUER_URL}`
  fi
fi

if [[ -z "${KO_DOCKER_REPO}" ]]; then
  echo "Must specify env variable KO_DOCKER_REPO"
  exit 1
fi

if [[ -z "${FULCIO_URL}" ]]; then
  echo "Must specify env variable FULCIO_URL"
  exit 1
fi

if [[ -z "${REKOR_URL}" ]]; then
  echo "Must specify env variable REKOR_URL"
  exit 1
fi

if [[ -z "${SIGSTORE_CT_LOG_PUBLIC_KEY_FILE}" ]]; then
  echo "must specify env variable SIGSTORE_CT_LOG_PUBLIC_KEY_FILE"
  exit 1
fi

if [[ "${NON_REPRODUCIBLE}"=="1" ]]; then
  echo "creating non-reproducible build by adding a timestamp"
  export TIMESTAMP=`date +%s`
else
  export TIMESTAMP="TIMESTAMP"
fi

# Trust our own custom Rekor API
export SIGSTORE_TRUST_REKOR_API_PUBLIC_KEY=1

# Publish the first test image
echo '::group:: publish test image demoimage'
pushd $(mktemp -d)
go mod init example.com/demo
cat <<EOF > main.go
package main
import "fmt"
func main() {
  fmt.Println("hello world TIMESTAMP")
}
EOF

sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoimage=`ko publish -B example.com/demo`
echo Created image $demoimage
popd
echo '::endgroup::'

# Publish the second test image
echo '::group:: publish test image demoimage'
pushd $(mktemp -d)
go mod init example.com/demo
cat <<EOF > main.go
package main
import "fmt"
func main() {
  fmt.Println("hello world 2 TIMESTAMP")
}
EOF
sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoimage2=`ko publish -B example.com/demo`
popd
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy with keyless signing'
kubectl apply -f ./test/testdata/cosigned/e2e/cip-keyless.yaml
echo '::endgroup::'

echo '::group:: Sign demo image'
COSIGN_EXPERIMENTAL=1 ./cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

echo '::group:: Verify demo image'
COSIGN_EXPERIMENTAL=1 ./cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Create test namespace and label for verification'
kubectl create namespace demo-keyless-signing
kubectl label namespace demo-keyless-signing cosigned.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: test job success'
# We signed this above, this should work
if ! kubectl create -n demo-keyless-signing job demo --image=${demoimage} ; then
  echo Failed to create Job in namespace with matching signature!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

# We did not sign this, should fail
echo '::group:: test job rejection'
if kubectl create -n demo-keyless-signing job demo2 --image=${demoimage2} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with unsigned image
fi
echo '::endgroup::'

echo '::group:: Add cip with identities that match issuer/subject'
kubectl apply -f ./test/testdata/cosigned/e2e/cip-keyless-with-identities.yaml
# make sure the reconciler has enough time to update the configmap
sleep 5
echo '::endgroup::'

# This has correct issuer/subject, so should work
echo '::group:: test job success with identities'
if ! kubectl create -n demo-keyless-signing job demo-identities-works --image=${demoimage} ; then
  echo Failed to create Job in namespace with matching issuer/subject!
  exit 1
else
  echo Succcessfully created Job with signed image keyless
fi
echo '::endgroup::'

echo '::group:: Add cip with identities that do not match issuer/subject'
kubectl apply -f ./test/testdata/cosigned/e2e/cip-keyless-with-identities-mismatch.yaml
# make sure the reconciler has enough time to update the configmap
sleep 5
echo '::endgroup::'

echo '::group:: test job block'
if kubectl create -n demo-keyless-signing job demo-identities-works --image=${demoimage} ; then
  echo Failed to block Job in namespace with non matching issuer and subject!
  exit 1
else
  echo Succcessfully blocked Job with mismatching issuer and subject
fi
echo '::endgroup::'

echo '::group:: Remove mismatching cip, start fresh for key'
kubectl delete cip --all
sleep 5
echo '::endgroup::'

echo '::group:: Generate New Signing Key For Colocated Signature'
COSIGN_PASSWORD="" ./cosign generate-key-pair
mv cosign.key cosign-colocated-signing.key
mv cosign.pub cosign-colocated-signing.pub
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Key Signing'
yq '. | .spec.authorities[0].key.data |= load_str("cosign-colocated-signing.pub")' \
  ./test/testdata/cosigned/e2e/cip-key.yaml | \
  kubectl apply -f -
echo '::endgroup::'

echo '::group:: Create and label new namespace for verification'
kubectl create namespace demo-key-signing
kubectl label namespace demo-key-signing cosigned.sigstore.dev/include=true

echo '::group:: Verify blocks unsigned with the key'
if kubectl create -n demo-key-signing job demo --image=${demoimage}; then
  echo Failed to block unsigned Job creation!
  exit 1
fi
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign key'
COSIGN_PASSWORD="" ./cosign sign --key cosign-colocated-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
./cosign verify --key cosign-colocated-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: test job success'
# We signed this above, this should work
if ! kubectl create -n demo-key-signing job demo --image=${demoimage} ; then
  echo Failed to create Job in namespace after signing with key!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup:: test job success'

echo '::group:: test job rejection'
# We did not sign this, should fail
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with unsigned image
fi
echo '::endgroup::'

echo '::group:: Generate New Signing Key For Remote Signature'
COSIGN_PASSWORD="" ./cosign generate-key-pair
mv cosign.key cosign-remote-signing.key
mv cosign.pub cosign-remote-signing.pub
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Remote Public Key But Missing Source'
yq '. | .metadata.name = "image-policy-remote-source"
    | .spec.authorities[0].key.data |= load_str("cosign-remote-signing.pub")' \
  ./test/testdata/cosigned/e2e/cip-key.yaml | \
  kubectl apply -f -
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign remote key'
COSIGN_PASSWORD="" COSIGN_REPOSITORY="${KO_DOCKER_REPO}/remote-signature" ./cosign sign --key cosign-remote-signing.key --force --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign remote key'
if ./cosign verify --key cosign-remote-signing.pub --allow-insecure-registry ${demoimage}; then
  echo "Signature should not have been verified unless COSIGN_REPOSITORY was defined"
  exit 1
fi

if ! COSIGN_REPOSITORY="${KO_DOCKER_REPO}/remote-signature" ./cosign verify --key cosign-remote-signing.pub --allow-insecure-registry ${demoimage}; then
  echo "Signature should have been verified when COSIGN_REPOSITORY was defined"
  exit 1
fi
echo '::endgroup::'

echo '::group:: Create test namespace and label for remote key verification'
kubectl create namespace demo-key-remote
kubectl label namespace demo-key-remote cosigned.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Verify with three CIP, one without correct Source set'
if kubectl create -n demo-key-remote job demo --image=${demoimage}; then
  echo Failed to block unsigned Job creation!
  exit 1
fi
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Remote Public Key With Source'
yq '. | .metadata.name = "image-policy-remote-source"
    | .spec.authorities[0].key.data |= load_str("cosign-remote-signing.pub")
    | .spec.authorities[0] += {"source": [{"oci": env(KO_DOCKER_REPO)+"/remote-signature"}]}' \
  ./test/testdata/cosigned/e2e/cip-key.yaml | \
  kubectl apply -f -
echo '::endgroup::'

echo '::group:: Verify with three CIP, one with correct Source set'
# We signed this above and applied remote signature source location above
if ! kubectl create -n demo-key-remote job demo --image=${demoimage}; then
  echo Failed to create Job in namespace without label!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

# Just to take stock of where we are at this point.
# We have two images $demoimage and $demoimage2.
# $demoimage has been signed two times, both with the
# 'key' and 'keyless'. $demoimage 2 has not been signed with anything,
# so let's create a policy that requires both a keyless and keyful
# signature on the image, as well as two attestations signed by the keyless
# one vuln attestation that's signed by key.
echo '::group:: Remove existing cips to get a fresh start'
kubectl delete cip --all
echo '::endgroup::'

echo '::group:: Generate New Signing Key For Remote Signature'
COSIGN_PASSWORD="" ./cosign generate-key-pair
echo '::endgroup::'

echo '::group:: Add cip for two signatures and two attestations'
yq '. | .spec.authorities[1].key.data |= load_str("cosign.pub") | .spec.authorities[3].key.data |= load_str("cosign.pub")' ./test/testdata/cosigned/e2e/cip-requires-two-signatures-and-two-attestations.yaml | kubectl apply -f -
echo '::endgroup::'

KUBECTL_OUT_FILE=./kubectl.output

echo '::group:: test job rejection'
# We signed this with key, but there are other things that will fail.
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with unsigned image
  if ! grep -q 'no matching signatures' ${KUBECTL_OUT_FILE} ; then
    echo Did not get expected failure message, wanted no matching signatures, got
    cat ${KUBECTL_OUT_FILE}
    exit 1
  fi
fi
echo '::endgroup::'

echo '::group:: Sign demoimage2 with key'
COSIGN_PASSWORD="" ./cosign sign --key cosign.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage2}
echo '::endgroup::'

echo '::group:: Verify demoimage2 with cosign key'
./cosign verify --key cosign.pub --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage2}
echo '::endgroup::'

echo '::group:: test job rejection'
# We signed this with key, but needs two signatures
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with only one signature on image
  if ! grep -q 'no matching signatures' ${KUBECTL_OUT_FILE} ; then
    echo Did not get expected failure message, wanted no matching signatures, got
    cat ${KUBECTL_OUT_FILE}
    exit 1
  fi
fi
echo '::endgroup::'

echo '::group:: Sign demoimage2 with keyless'
# Tests run for awhile, grab a fresh OIDC_TOKEN
export OIDC_TOKEN=`curl -s ${ISSUER_URL}`
COSIGN_EXPERIMENTAL=1 ./cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage2} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

echo '::group:: Verify demoimage2'
COSIGN_EXPERIMENTAL=1 ./cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage2}
echo '::endgroup::'

echo '::group:: test job rejection'
# We signed this with key and keyless, but there are other things that will fail.
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to block Job with no attestations creation!
  exit 1
else
  echo Successfully blocked Job creation with only one signature on image
  if ! grep -q 'validate signatures with fulcio: no matching attestations' ${KUBECTL_OUT_FILE} ; then
    echo Did not get expected failure message, wanted validate signatures with fulcio: no matching attestations got
    cat ${KUBECTL_OUT_FILE}
    exit 1
  fi
fi
echo '::endgroup::'

echo '::group:: Create one keyless attestation and verify it'
echo -n 'foobar e2e test' > ./predicate-file-custom
COSIGN_EXPERIMENTAL=1 ./cosign attest --predicate ./predicate-file-custom --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --force ${demoimage2} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 ./cosign verify-attestation --type=custom --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage2}
echo '::endgroup::'

echo '::group:: test job rejection'
# We signed this with key and keyless and it has keyless attestation, but there are other things that will fail.
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with only one signature on image
  if ! grep -q 'failed policy: image-policy-requires-two-signatures-two-attestations' ${KUBECTL_OUT_FILE} ; then
    echo Did not get expected failure message, wanted failed policy: image-policy-requires-two-signatures-two-attestations got
    cat ${KUBECTL_OUT_FILE}
    exit 1
  fi
fi
echo '::endgroup::'

# Then add the vuln attestation with key, we have then one attestation
# with key, one with keyless, but that's still not enough, so will fail.
echo '::group:: Create one key attestation and verify it'
COSIGN_PASSWORD="" ./cosign attest --predicate ./test/testdata/attestations/vuln-predicate.json --rekor-url ${REKOR_URL} --type=vuln --key ./cosign.key --allow-insecure-registry --force ${demoimage2}

./cosign verify-attestation --type vuln --key ./cosign.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage2}
echo '::endgroup::'

echo '::group:: test job rejection'
# We signed this with key and keyless and it has one keyless attestation and one with key, but there are other things that will fail.
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with only one signature on image
  if ! grep -q 'failed policy: image-policy-requires-two-signatures-two-attestations' ${KUBECTL_OUT_FILE} ; then
    echo Did not get expected failure message, wanted failed policy: image-policy-requires-two-signatures-two-attestations got
    cat ${KUBECTL_OUT_FILE}
    exit 1
  fi
fi
echo '::endgroup::'

echo '::group:: Create vuln keyless attestation and verify it'
COSIGN_EXPERIMENTAL=1 ./cosign attest --predicate ./test/testdata/attestations/vuln-predicate.json --type=vuln --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --force ${demoimage2} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 ./cosign verify-attestation --type=vuln --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage2}
echo '::endgroup::'

echo '::group:: test job success'
# We signed this with key and keyless and it has keyless attestation, but there are other things that will fail.
if ! kubectl create -n demo-key-signing job demo2 --image=${demoimage2} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to create job that should have been allowed through!
  cat ${KUBECTL_OUT_FILE}
  exit 1
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-key-signing demo-keyless-signing
rm cosign*.key cosign*.pub
echo '::endgroup::'
