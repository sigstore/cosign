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
echo '::group:: invalid policy: both glob and regex'

cat > policy.yaml <<EOF
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    regex: image.*
    authorities:
    - key:
        data: "---somedata---"
EOF

if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: key with multiple properties'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - key:
        data: "---somedata---"
        kms: "kms://url"
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'


echo '::group:: invalid policy: empty key'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - key: {}

EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty identities'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - keyless:
        identities: []
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty keyless ref'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - keyless: {}
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: both valid key and keyless'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - keyless:
        identities:
        - issuer: "issue-details"
      key:
        data: "---somekey---"
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty key and keyless'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - keyless: {}
      key: {}

EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty authorities'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**v
    authorities: []
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: multiple valid properties in keyless ref'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: image**
    authorities:
    - keyless:
        ca-key:
          secretRef:
            name: ca-key-secret
            namespace: some-namespace
        identities:
        - issuer: "issue-details"
          subject: "subject-details"
EOF
if kubectl create -f policy.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: Valid policy:'
cat > policy.yaml <<EOF
---
apiVersion: cosigned.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - regex: images.*
    authorities:
    - key:
        data: "---another-public-key---"
  - glob: image**
    authorities:
    - keyless:
        ca-key:
          secretRef:
            name: ca-key-secret
            namespace: some-namespace
    - keyless:
        identities:
        - issuer: "issue-details"
          subject: "subject-details"
    - keyless:
        identities:
        - issuer: "issue-details1"
    - key:
        data: "---some-key---"
    - key:
        kms: "kms://key/path"
    - key:
        secretRef:
          name: secret-name
          namespace: secret-namespce
EOF
if kubectl create -f policy.yaml ; then
  echo Valid prolicy was created
  kubectl delete -f policy.yaml
else
  echo Valid policy should be created
  exit 1
fi
echo '::endgroup::'
