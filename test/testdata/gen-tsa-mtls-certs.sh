#!/usr/bin/env bash
#
# Copyright 2023 The Sigstore Authors.
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
# This script generates certificates for testing
# mTLS connection from 'cosign' command to the TSA server.
#
# Requirements:
# step CLI tool - https://smallstep.com/docs/step-cli/
# openssl command line tool: https://www.openssl.org/docs/manmaster/man1/openssl.html

step certificate create "Sigstore Cosign Test CA" tsa-mtls-ca.crt tsa-mtls-ca.key --profile=root-ca --insecure --no-password --not-before=-10m --not-after=+87600h --force
step certificate create tsa-mtls-server tsa-mtls-server.crt tsa-mtls-server.key --san "server.example.com" --profile leaf --ca tsa-mtls-ca.crt --ca-key tsa-mtls-ca.key --insecure --no-password --not-before=-10m --not-after=+87600h --force
step certificate create tsa-mtls-client tsa-mtls-client.crt tsa-mtls-client.key --profile leaf --ca tsa-mtls-ca.crt --ca-key tsa-mtls-ca.key --insecure --no-password --not-before=-10m --not-after=+87600h --force
rm -fr tsa-mtls-ca.key

