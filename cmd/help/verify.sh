#!/usr/bin/env bash

# Copyright 2021 The Sigstore Authors
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

set -e

# Verify that generated Markdown docs are up-to-date.
tmpdir=$(mktemp -d)
go run -tags pivkey,pkcs11key,cgo cmd/help/main.go --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: go run -tags pivkey,pkcs11key,cgo ./cmd/help/"
echo "###########################################"
diff -Naur "$tmpdir" doc/
