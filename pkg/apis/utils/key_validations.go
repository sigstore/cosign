// Copyright 2022 The Sigstore Authors.
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

package utils

import (
	"crypto/x509"
	"encoding/pem"
)

func IsValidKey(b []byte) bool {
	valid := true
	pems, validPEM := parsePEMKey(b)
	if !validPEM {
		return false
	}

	for _, p := range pems {
		_, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return false
		}
	}

	return valid
}

func parsePEMKey(b []byte) ([]*pem.Block, bool) {
	pemKey, rest := pem.Decode(b)
	valid := true
	if pemKey == nil {
		return nil, false
	}
	pemBlocks := []*pem.Block{pemKey}

	if len(rest) > 0 {
		list, check := parsePEMKey(rest)
		return append(pemBlocks, list...), check
	}
	return pemBlocks, valid
}
