//
// Copyright 2021 The Sigstore Authors.
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

package sign

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
)

// TestSignCmdLocalKeyAndSk verifies the SignCmd returns an error
// if both a local key path and a sk are specified
func TestSignCmdLocalKeyAndSk(t *testing.T) {
	ro := &options.RootOptions{Timeout: options.DefaultTimeout}

	for _, ko := range []options.KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		so := options.SignOptions{}
		err := SignCmd(ro, ko, so, nil)
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}

func Test_ParseOCIReference(t *testing.T) {
	var tests = []struct {
		ref             string
		expectedWarning string
	}{
		{"image:bytag", "WARNING: Image reference image:bytag uses a tag, not a digest"},
		{"image:bytag@sha256:abcdef", ""},
		{"image:@sha256:abcdef", ""},
	}
	for _, tt := range tests {
		stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
			ParseOCIReference(ctx, tt.ref)
		})
		if len(tt.expectedWarning) > 0 {
			assert.Contains(t, stderr, tt.expectedWarning, stderr, "bad warning message")
		} else {
			assert.Empty(t, stderr, "expected no warning")
		}
	}
}
