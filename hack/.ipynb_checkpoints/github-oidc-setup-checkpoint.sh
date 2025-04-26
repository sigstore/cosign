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

# Idempotent script.
#
# Commands based off of Google blog post
# https://cloud.google.com/blog/products/identity-security/enabling-keyless-authentication-from-github-actions
#
# One addition is the attribute.repository=assertion.repository mapping.
# This allows it to be pinned to given repo.

set -o errexit
set -o nounset
set -o pipefail
set -o verbose
set -o xtrace

PROJECT_ID="projectsigstore"
PROJECT_NUMBER="498091336538"
POOL_NAME="githubactions"
PROVIDER_NAME="sigstore-cosign"
LOCATION="global"
REPO="sigstore/cosign"
SERVICE_ACCOUNT_ID="github-actions-cosign"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

# Create workload identity pool if not present.
if ! (gcloud iam workload-identity-pools describe "${POOL_NAME}" --location=${LOCATION}); then
  gcloud iam workload-identity-pools create "${POOL_NAME}" \
    --project="${PROJECT_ID}" \
    --location="${LOCATION}" \
    --display-name="Github Actions Pool"
fi

# Create workload identity provider if not present.
if ! (gcloud iam workload-identity-pools providers describe "${PROVIDER_NAME}" --location="${LOCATION}" --workload-identity-pool="${POOL_NAME}"); then
  gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_NAME}" \
  --project="${PROJECT_ID}" \
  --location="${LOCATION}" \
  --workload-identity-pool="${POOL_NAME}" \
  --display-name="Github Actions Provider Cosign" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.aud=assertion.aud,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"
fi

# Create service account if not present.
if ! (gcloud iam service-accounts describe "${SERVICE_ACCOUNT}"); then
gcloud iam service-accounts create ${SERVICE_ACCOUNT_ID} \
  --description="Service account for Github Actions Cosign" \
  --display-name="Github Actions Cosign"
fi

# Adding binding is idempotent.
gcloud iam service-accounts add-iam-policy-binding "${SERVICE_ACCOUNT}" \
  --project="${PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/${LOCATION}/workloadIdentityPools/${POOL_NAME}/attribute.repository/${REPO}"

# Adding binding is idempotent.
# Used for kicking off cloud build.
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --project="${PROJECT_ID}" \
  --role="roles/cloudbuild.builds.editor" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

# Adding binding is idempotent.
# Permission needed to run `gcloud builds`
# https://cloud.google.com/build/docs/securing-builds/configure-access-to-resources#granting_permissions_to_run_gcloud_commands
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --project="${PROJECT_ID}" \
  --role="roles/serviceusage.serviceUsageConsumer" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"
