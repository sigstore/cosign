// +build gofuzz

// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"bytes"
	"fmt"

	"github.com/sigstore/cosign/cmd/cosign/cli"
)

func FuzzGetPassword(data []byte) int {
	original := cli.Read
	cli.Read = func() func() ([]byte, error) {
		return func() ([]byte, error) {
			return data, nil
		}
	}
	defer func() { cli.Read = original }()
	p, err := cli.GetPass(true)
	if err != nil {
		panic(fmt.Sprintf("error getting password: %v", err))
	}
	// the password we got back is not what was entered
	if bytes.Compare(p, data) != 0 {
		panic(fmt.Sprintf("input does not match output: %s %s", string(p), string(data)))
	}
	return 0
}
