// Copyright 2023 The Sigstore Authors.
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

package attest

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPredicateReader(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantErr    bool
		wantStdin  bool
		createFile bool
	}{
		{
			name:      "standard input",
			path:      "-",
			wantStdin: true,
		},
		{
			name:       "regular file",
			path:       "payload.json",
			createFile: true,
		},
		{
			name:    "missing file",
			path:    "payload.json",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pf := tc.path
			if tc.createFile {
				pf = path.Join(t.TempDir(), tc.path)
				err := os.WriteFile(pf, []byte("payload"), 0644)
				require.NoError(t, err)
			}

			got, err := predicateReader(pf)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tc.wantStdin {
				require.Same(t, os.Stdin, got)
			} else {
				require.NotSame(t, os.Stdin, got)
			}
		})
	}
}
