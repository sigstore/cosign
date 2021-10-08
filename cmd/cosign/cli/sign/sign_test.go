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

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
)

// TestSignCmdLocalKeyAndSk verifies the SignCmd returns an error
// if both a local key path and a sk are specified
func TestSignCmdLocalKeyAndSk(t *testing.T) {
	ctx := context.Background()

	for _, ko := range []KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		err := SignCmd(ctx, ko, options.RegistryOptions{}, nil, nil, "", false, "", false, false, "")
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}
