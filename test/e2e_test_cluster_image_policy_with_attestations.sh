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

# To simplify testing failures, use this function to execute a kubectl to create
# our job and verify that the failure is expected.
assert_error() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.failure.out"
  match="$@"
  echo looking for ${match}
  if kubectl create -n ${NS} job demo --image=${demoimage} 2> ${KUBECTL_OUT_FILE} ; then
    echo Failed to block unsigned Job creation!
    exit 1
  else
    echo Successfully blocked Job creation with expected error: "${match}"
    if ! grep -q "${match}" ${KUBECTL_OUT_FILE} ; then
      echo Did not get expected failure message, wanted "${match}", got
      cat ${KUBECTL_OUT_FILE}
      exit 1
    fi
  fi
}

# Publish test image
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

echo '::group:: Create and label new namespace for verification'
kubectl create namespace demo-attestations
kubectl label namespace demo-attestations cosigned.sigstore.dev/include=true
export NS=demo-attestations
echo '::endgroup::'

echo '::group:: Create CIP that requires keyless signature and custom attestation with policy'
kubectl apply -f ./test/testdata/cosigned/e2e/cip-keyless-with-attestations.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

# This image has not been signed at all, so should get auto-reject
echo '::group:: test job rejection'
expected_error='no matching signatures'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Sign demoimage with keyless'
COSIGN_EXPERIMENTAL=1 ./cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

# This image has been signed, but does not have an attestation, so should fail.
echo '::group:: test job rejection'
expected_error='no matching attestations'
assert_error ${expected_error}
echo '::endgroup::'

# Ok, cool. So attest and it should pass.
echo '::group:: Create one keyless attestation and verify it'
echo -n 'foobar e2e test' > ./predicate-file-custom
COSIGN_EXPERIMENTAL=1 ./cosign attest --predicate ./predicate-file-custom --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --force ${demoimage} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 ./cosign verify-attestation --type=custom --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: test job success'
# We signed this with keyless and it has a keyless attestation, so should
# pass.
export KUBECTL_SUCCESS_FILE="/tmp/kubectl.success.out"
if ! kubectl create -n ${NS} job demo --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with keyless signature and an attestation
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with keyless signature and an attestation
fi
echo '::endgroup::'

echo '::group:: Generate New Signing Key that we use for key-ful signing'
COSIGN_PASSWORD="" ./cosign generate-key-pair
echo '::endgroup::'

# Ok, so now we have satisfied the keyless requirements, one signature, one
# custom attestation. Let's now do it for 'keyful' one.
echo '::group:: Create CIP that requires a keyful signature and an attestation'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub") | .spec.authorities[1].key.data |= load_str("cosign.pub")' ./test/testdata/cosigned/e2e/cip-key-with-attestations.yaml | kubectl apply -f -
# allow things to propagate
sleep 5
echo '::endgroup::'

# This image has been signed with keyless, but does not have a keyful signature
# so should fail
echo '::group:: test job rejection'
expected_error='no matching signatures'
assert_error ${expected_error}
echo '::endgroup::'

# Sign it with key
echo '::group:: Sign demoimage with key, and add to rekor'
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" ./cosign sign --key cosign.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
COSIGN_EXPERIMENTAL=1 ./cosign verify --key cosign.pub --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

# This image has been signed with key, but does not have a key attestation
# so should fail
echo '::group:: test job rejection'
expected_error='no matching attestations'
assert_error ${expected_error}
echo '::endgroup::'

# Fine, so create an attestation for it that's different from the keyless one
echo '::group:: create keyful attestation, add add to rekor'
echo -n 'foobar key e2e test' > ./predicate-file-key-custom
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" ./cosign attest --predicate ./predicate-file-key-custom --rekor-url ${REKOR_URL} --key ./cosign.key --allow-insecure-registry --force ${demoimage}

COSIGN_EXPERIMENTAL=1 ./cosign verify-attestation --key ./cosign.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: test job success with key / keyless'
# We signed this with keyless and key and it has a key/keyless attestation, so
# should pass.
if ! kubectl create -n ${NS} job demo2 --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with both key/keyless signatures and attestations
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with keyless/key signature and an attestations
fi
echo '::endgroup::'

# So at this point, we have two CIP, one that requires keyless/key sig
# and attestations with both. Let's take it up a notch.
# Let's create a policy that requires both a keyless and keyful
# signature on the image, as well as two attestations signed by the keyless and
# one custom attestation that's signed by key.
# Note we have to bake in the inline data from the keys above
echo '::group:: Add cip for two signatures and two attestations'
yq '. | .spec.authorities[1].key.data |= load_str("cosign.pub") | .spec.authorities[3].key.data |= load_str("cosign.pub")' ./test/testdata/cosigned/e2e/cip-requires-two-signatures-and-two-attestations.yaml | kubectl apply -f -
echo '::endgroup::'

# TODO(vaikas): Enable the remaining tests once we sort out how to write
# a valid CUE policy, or once #1787 goes in try implementing a Rego one.
echo 'Not testing the CIP policy evaluation yet'
exit 0

# The CIP policy is the one that should fail now because it doesn't have enough
# attestations
echo '::group:: test job rejection'
expected_error='no matching attestations'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Create vuln keyless attestation and verify it'
COSIGN_EXPERIMENTAL=1 ./cosign attest --predicate ./test/testdata/attestations/vuln-predicate.json --type=vuln --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --force ${demoimage} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 ./cosign verify-attestation --type=vuln --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: test job success'
# We signed this with key and keyless and it has two keyless attestations and
# it has one key attestation, so it should succeed.
if ! kubectl create -n ${NS} job demo3 --image=${demoimage} 2> ./${KUBECTL_OUT_FILE} ; then
  echo Failed to create job that has two signatures and 3 attestations
  cat ${KUBECTL_OUT_FILE}
  exit 1
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-attestations
rm cosign.key cosign.pub
echo '::endgroup::'
