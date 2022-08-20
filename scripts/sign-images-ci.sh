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
: "${GITHUB_RUN_ID:?Environment variable empty or not defined.}"
: "${GITHUB_RUN_ATTEMPT:?Environment variable empty or not defined.}"

export COSIGN_EXPERIMENTAL=1
COSIGN_CLI=./cosign

if [[ ! -f cosignImagerefs ]]; then
    echo "cosignImagerefs not found"
    exit 1
fi

if [[ ! -f sgetImagerefs ]]; then
    echo "sgetImagerefs not found"
    exit 1
fi

echo "Signing cosign images using Keyless..."

$COSIGN_CLI sign -a sha="$GIT_HASH" -a run_id="$GITHUB_RUN_ID" -a run_attempt="$GITHUB_RUN_ATTEMPT" "$(cat cosignImagerefs)"
$COSIGN_CLI sign -a sha="$GIT_HASH" -a run_id="$GITHUB_RUN_ID" -a run_attempt="$GITHUB_RUN_ATTEMPT" "$(cat sgetImagerefs)"
