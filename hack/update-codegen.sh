#!/usr/bin/env bash

# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

pushd $(dirname "$0")/..
# Removed by update-deps
echo === Vendoring scripts
go mod vendor

source $(dirname $0)/../vendor/knative.dev/hack/codegen-library.sh

TMP_DIR="$(mktemp -d)"
trap 'rm -rf ${TMP_DIR}' EXIT
# Use the same go mod cache to speed things up.
export GOMODCACHE=${GOPATH}/pkg/mod
export GOPATH=${TMP_DIR}


TMP_REPO_PATH="${TMP_DIR}/src/github.com/sigstore/cosign"
mkdir -p "$(dirname "${TMP_REPO_PATH}")" && ln -s "${REPO_ROOT_DIR}" "${TMP_REPO_PATH}"

echo "=== Update Codegen for ${MODULE_NAME}"

group "Kubernetes Codegen"

# generate the code with:
# --output-base    because this script should also be able to run inside the vendor dir of
#                  k8s.io/kubernetes. The output-base is needed for the generators to output into the vendor dir
#                  instead of the $GOPATH directly. For normal projects this can be dropped.
${CODEGEN_PKG}/generate-groups.sh "deepcopy,client,informer,lister" \
  github.com/sigstore/cosign/pkg/client github.com/sigstore/cosign/pkg/apis \
  "cosigned:v1alpha1 cosigned:v1beta1" \
  --go-header-file ${REPO_ROOT_DIR}/hack/boilerplate/boilerplate.go.txt

group "Knative Codegen"

# Knative Injection
${KNATIVE_CODEGEN_PKG}/hack/generate-knative.sh "injection" \
  github.com/sigstore/cosign/pkg/client github.com/sigstore/cosign/pkg/apis \
  "cosigned:v1alpha1 cosigned:v1beta1" \
  --go-header-file ${REPO_ROOT_DIR}/hack/boilerplate/boilerplate.go.txt

group "Update CRD Schema"

go run $(dirname $0)/../cmd/schema/ dump ClusterImagePolicy \
  | yq eval-all --inplace 'select(fileIndex == 0).spec.versions[0].schema.openAPIV3Schema = select(fileIndex == 1) | select(fileIndex == 0)' \
  $(dirname $0)/../config/300-clusterimagepolicy.yaml -

group "Update deps post-codegen"

# Make sure our dependencies are up-to-date
${REPO_ROOT_DIR}/hack/update-deps.sh
