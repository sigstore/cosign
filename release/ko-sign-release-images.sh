#!/usr/bin/env bash

# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"";
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

: "${GIT_HASH:?Environment variable empty or not defined.}"
: "${GIT_VERSION:?Environment variable empty or not defined.}"
: "${PROJECT_ID:?Environment variable empty or not defined.}"
: "${KEY_LOCATION:?Environment variable empty or not defined.}"
: "${KEY_RING:?Environment variable empty or not defined.}"
: "${KEY_NAME:?Environment variable empty or not defined.}"
: "${KEY_VERSION:?Environment variable empty or not defined.}"


if [[ ! -f cosignImagerefs ]]; then
    echo "cosignImagerefs not found"
    exit 1
fi

if [[ ! -f sgetImagerefs ]]; then
    echo "sgetImagerefs not found"
    exit 1
fi

echo "Signing cosign images with GCP KMS Key..."

cosign sign --force --key "gcpkms://projects/$PROJECT_ID/locations/$KEY_LOCATION/keyRings/$KEY_RING/cryptoKeys/$KEY_NAME/versions/$KEY_VERSION" -a GIT_HASH="$GIT_HASH" -a GIT_VERSION="$GIT_VERSION" $(cat cosignImagerefs)
cosign sign --force --key "gcpkms://projects/$PROJECT_ID/locations/$KEY_LOCATION/keyRings/$KEY_RING/cryptoKeys/$KEY_NAME/versions/$KEY_VERSION" -a GIT_HASH="$GIT_HASH" -a GIT_VERSION="$GIT_VERSION" $(cat sgetImagerefs)

echo "Signing images with Keyless..."
cosign sign --force -a GIT_HASH="$GIT_HASH" -a GIT_VERSION="$GIT_VERSION" $(cat cosignImagerefs)
cosign sign --force -a GIT_HASH="$GIT_HASH" -a GIT_VERSION="$GIT_VERSION" $(cat sgetImagerefs)
