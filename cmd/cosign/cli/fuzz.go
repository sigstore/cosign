/*
Copyright The Rekor Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cli

import (
	"bytes"
	"fmt"
)

func FuzzGetPassword(data []byte) int {
	read = func() ([]byte, error) {
		return data, nil
	}
	p, err := getPass(true)
	if err != nil {
		return 1
	}
	// the password we got back is not what was entered
	if bytes.Compare(p, data) != 0 {
		panic(fmt.Sprintf("input does not match output: %s %s", string(p), string(data)))
	}
	return 0
}
