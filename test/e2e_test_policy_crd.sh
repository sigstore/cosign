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

echo '::group:: Invalid policy tests:'
for i in `ls ./test/testdata/cosigned/invalid/`
do
  if kubectl create -f ./test/testdata/cosigned/invalid/$i ; then
    echo "${i} policy created when it should not have"
    exit 1
  else
    echo "${i} rejected as expected"
  fi
done
echo '::endgroup:: Invalid policy test:'

echo '::group:: Valid policy test:'
for i in `ls ./test/testdata/cosigned/valid/`
do
  if kubectl create -f ./test/testdata/cosigned/valid/$i ; then
    echo "${i} created as expected"
  else
    echo "${i} failed when it should not have"
    exit 1
  fi

  kubectl delete -f ./test/testdata/cosigned/valid/$i --ignore-not-found=true
done

echo '::endgroup:: Valid policy test:'
