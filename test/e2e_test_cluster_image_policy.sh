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
  echo Failed to create Job in namespace without label!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

echo '::group:: Add cip with identities that match issuer/subject'
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

echo '::group:: Remove mismatching cip'
kubectl delete cip image-policy-keyless-with-identities-mismatch
sleep 5
echo '::endgroup::'

echo '::group:: Generate signing key'
COSIGN_PASSWORD="" ./cosign generate-key-pair
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Key Signing'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/cosigned/e2e/cip-key.yaml | kubectl apply -f -
echo '::endgroup::'

echo '::group:: Verify blocks unsigned with the key'
if kubectl create -n demo-key-signing job demo --image=${demoimage}; then
  echo Failed to block unsigned Job creation!
  exit 1
fi
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign key'
COSIGN_PASSWORD="" ./cosign sign --key cosign.key --force --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
./cosign verify --key cosign.pub --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Create and label new namespace for verification'
kubectl create namespace demo-key-signing
kubectl label namespace demo-key-signing cosigned.sigstore.dev/include=true

echo '::group:: test job success'
# We signed this above, this should work
if ! kubectl create -n demo-key-signing job demo --image=${demoimage} ; then
  echo Failed to create Job in namespace without label!
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

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-key-signing demo-keyless-signing
rm cosign.key cosign.pub
