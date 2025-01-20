//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestation

import (
	"bytes"
	"testing"
)

func FuzzGenerateStatement(f *testing.F) {
	f.Fuzz(func(_ *testing.T, predicate []byte, digest, repo string, stmttType int) {
		var statementType string
		switch stmttType % 9 {
		case 0:
			statementType = "slsaprovenance"
		case 1:
			statementType = "slsaprovenance02"
		case 2:
			statementType = "slsaprovenance1"
		case 3:
			statementType = "spdx"
		case 4:
			statementType = "spdxjson"
		case 5:
			statementType = "cyclonedx"
		case 6:
			statementType = "link"
		case 7:
			statementType = "vuln"
		case 8:
			statementType = "openvex"
		default:
			statementType = ""
		}
		opts := GenerateOpts{
			Predicate: bytes.NewReader(predicate),
			Type:      statementType,
			Digest:    digest,
			Repo:      repo,
		}
		GenerateStatement(opts)
	})
}
