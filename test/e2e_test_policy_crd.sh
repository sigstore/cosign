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
if kubectl create -f ./test/testdata/cosigned/invalid/both-regex-and-pattern.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: key with multiple properties'
if kubectl create -f ./test/testdata/cosigned/invalid/keyref-with-multiple-properties.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'


echo '::group:: invalid policy: empty key'
if kubectl create -f ./test/testdata/cosigned/invalid/empty-keyref.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty keyless ref'
if kubectl create -f ./test/testdata/cosigned/invalid/empty-keyless-ref.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: both valid key and keyless'
if kubectl create -f ./test/testdata/cosigned/invalid/valid-keyref-and-keylessref.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty key and keyless'
if kubectl create -f ./test/testdata/cosigned/invalid/empty-keyref-and-keylessref.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty identities'
if kubectl create -f ./test/testdata/cosigned/invalid/keylessref-with-empty-identities.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: empty authorities'
if kubectl create -f ./test/testdata/cosigned/invalid/keylessref-with-empty-authorities.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: invalid policy: multiple valid properties in keyless ref'
if kubectl create -f ./test/testdata/cosigned/invalid/keylessref-with-multiple-properties.yaml ; then
  echo Invalid policy should not be created!
  exit 1
else
  echo Invalid policy was rejected
fi
echo '::endgroup::'

echo '::group:: Valid policy:'
if kubectl create -f ./test/testdata/cosigned/valid/valid-policy.yaml ; then
  echo Valid prolicy was created
  kubectl delete -f ./test/testdata/cosigned/valid/valid-policy.yaml
else
  echo Valid policy should be created
  exit 1
fi
echo '::endgroup::'
