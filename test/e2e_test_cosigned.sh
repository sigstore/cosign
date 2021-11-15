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
DIGEST=$(ko publish -B ./cmd/sample)
cat > pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  generateName: pod-test-
spec:
  restartPolicy: Never
  containers:
  - name: sample
    image: $KO_DOCKER_REPO/sample
EOF
cat > distroless-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  generateName: pod-test-
spec:
  restartPolicy: Never
  containers:
  - name: sample
    image: gcr.io/distroless/base:debug
    command: [/busybox/sh, -c]
    args:
    - |
      echo Testing Fulcio verification
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
          image: $KO_DOCKER_REPO/sample
EOF

cat > cronjob.yaml <<EOF
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  generateName: cronjob-test-
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sample
            image: $KO_DOCKER_REPO/sample
          restartPolicy: Never
EOF
echo '::endgroup::'

cat > manykeys.pem <<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQaXTMA1eCVAGCTWxTe8ZQ0JVNSXV
A+6/ffM1bfNnq3AGkhGNfJTI3P0w1Y69gBTF/AfXhYuEc/SxmX0b3PwzWg==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE40I8/4Q4k7IhuJvesexymMH4mQa6
nD9c9iLu5S/Y5yjCDYtDTB7MzwTy+0RtIdIAv1ePBVGVQ/s7M2QDdrA8SQ==
-----END PUBLIC KEY-----
EOF

echo '::endgroup::'


echo '::group:: enable verification'
kubectl label namespace default --overwrite cosigned.sigstore.dev/include=true
echo '::endgroup::'


echo '::group:: test pod success (Fulcio root)'
# This time it should succeed!
if ! kubectl create -f distroless-pod.yaml ; then
  echo Failed to create Pod signed by Fulcio!
  exit 1
else
  echo Successfully created Pod signed by Fulcio.
fi
echo '::endgroup::'


echo '::group:: setup verification-key'
# Update the cosign verification-key secret with a proper key pair.
cosign generate-key-pair k8s://cosign-system/verification-key
echo '::endgroup::'

echo '::group:: setup multiple verification-keys'
cosign public-key --key k8s://cosign-system/verification-key >> manykeys.pem

# Save the old key
kubectl get secret -n cosign-system verification-key -o=json | jq -r '.data["cosign.key"]' | base64 --decode > cosign.key
kubectl delete secret -n cosign-system  verification-key
kubectl create secret generic -n cosign-system verification-key --from-file=cosign.pub=manykeys.pem --from-literal=cosign.password=${COSIGN_PASSWORD} --from-file=cosign.key

echo '::group:: disable verification'
kubectl label namespace default --overwrite cosigned.sigstore.dev/include=false
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

echo '::group:: test cronjob success'
# This time it should succeed!
if ! kubectl create -f cronjob.yaml ; then
  echo Failed to create CronJob in namespace without label!
  exit 1
else
  echo Successfully created CronJob in namespace without label.
fi
echo '::endgroup::'

echo '::group:: enable verification'
kubectl label namespace default --overwrite cosigned.sigstore.dev/include=true
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

echo '::group:: test cronjob rejection'
if kubectl create -f cronjob.yaml ; then
  echo Failed to block CronJob creation!
  exit 1
else
  echo Successfully blocked CronJob creation.
fi
echo '::endgroup::'

echo '::group:: sign test image'
cosign sign --key k8s://cosign-system/verification-key $DIGEST
echo '::endgroup::'



echo '::group:: test pod digest resolution'
IMAGE=$(kubectl create --dry-run=server -f pod.yaml -oyaml | yq e '.spec.containers[0].image' -)

if [ "$IMAGE" != "$DIGEST" ] ; then
  echo Failed to resolve tag to digest!
  exit 1
else
  echo Successfully resolved tag to digest.
fi
echo '::endgroup::'

echo '::group:: test job digest resolution'
IMAGE=$(kubectl create --dry-run=server -f job.yaml -oyaml | yq e '.spec.template.spec.containers[0].image' -)

if [ "$IMAGE" != "$DIGEST" ] ; then
  echo Failed to resolve tag to digest!
  exit 1
else
  echo Successfully resolved tag to digest.
fi
echo '::endgroup::'

echo '::group:: test cronjob digest resolution'
IMAGE=$(kubectl create --dry-run=server -f cronjob.yaml -oyaml | yq e '.spec.jobTemplate.spec.template.spec.containers[0].image' -)

if [ "$IMAGE" != "$DIGEST" ] ; then
  echo Failed to resolve tag to digest!
  exit 1
else
  echo Successfully resolved tag to digest.
fi
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

echo '::group:: test cronjob success'
# This time it should succeed!
if ! kubectl create -f cronjob.yaml ; then
  echo Failed to create CronJob with properly signed image!
  exit 1
else
  echo Successfully created CronJob from signed image.
fi
echo '::endgroup::'
