//
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

package envvar

import (
	"context"
	"fmt"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign/env"
)

func TestEnvVar(t *testing.T) {
	ctx := context.Background()
	token := "tacocat"

	for _, tc := range []struct {
		envmap map[string]string
		want   bool
	}{
		{
			envmap: map[string]string{
				env.VariableSigstoreIDToken.String(): token,
			},
			want: true,
		},
		{
			want: false,
		},
	} {
		t.Run(fmt.Sprint(tc.want), func(t *testing.T) {
			for k, v := range tc.envmap {
				t.Setenv(k, v)
			}
			e := &envvar{}

			if enabled := e.Enabled(ctx); enabled != tc.want {
				t.Errorf("Enabled: want %t, got %t", tc.want, enabled)
			}

			got, err := e.Provide(ctx, "")
			if err != nil {
				t.Fatalf("Provide: %v", err)
			}
			want := ""
			if tc.want {
				want = token
			}
			if got != want {
				t.Fatalf("Provide: want %s, got %s", want, got)
			}
		})
	}
}
