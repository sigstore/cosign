#!/bin/bash
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

set -ex


echo '::group:: publish test image'
DIGEST=$(ko publish ./cmd/sample)
cat > pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  generateName: pod-test-
spec:
  restartPolicy: Never
  containers:
  - name: sample
    image: $DIGEST
EOF
cat > job.yaml <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  generateName: job-test-
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: sample
          image: $DIGEST
EOF
echo '::endgroup::'


echo '::group:: test pod success (before labeling)'
# This time it should succeed!
if ! kubectl create -f pod.yaml ; then
  echo Failed to create Pod in namespace without label!
  exit 1
else
  echo Successfully created Pod in namespace without label.
fi
echo '::endgroup::'


echo '::group:: test job success'
# This time it should succeed!
if ! kubectl create -f job.yaml ; then
  echo Failed to create Job in namespace without label!
  exit 1
else
  echo Successfully created Job in namespace without label.
fi
echo '::endgroup::'


echo '::group:: enable verification'
kubectl label namespace default cosigned.sigstore.dev/include=true
echo '::endgroup::'


echo '::group:: test pod rejection'
if kubectl create -f pod.yaml ; then
  echo Failed to block Pod creation!
  exit 1
else
  echo Successfully blocked Pod creation.
fi
echo '::endgroup::'


echo '::group:: test job rejection'
if kubectl create -f job.yaml ; then
  echo Failed to block Job creation!
  exit 1
else
  echo Successfully blocked Job creation.
fi
echo '::endgroup::'


echo '::group:: sign test image'
cosign sign -key k8s://cosign-system/verification-key $DIGEST
echo '::endgroup::'


echo '::group:: test pod success'
# This time it should succeed!
if ! kubectl create -f pod.yaml ; then
  echo Failed to create Pod with properly signed image!
  exit 1
else
  echo Successfully created Pod from signed image.
fi
echo '::endgroup::'


echo '::group:: test job success'
# This time it should succeed!
if ! kubectl create -f job.yaml ; then
  echo Failed to create Job with properly signed image!
  exit 1
else
  echo Successfully created Job from signed image.
fi
echo '::endgroup::'
