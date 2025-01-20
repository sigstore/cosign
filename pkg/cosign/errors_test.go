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

package cosign

import (
	"fmt"
	"testing"

	"errors"
)

func TestErrors(t *testing.T) {
	for _, want := range []error{
		&VerificationFailure{fmt.Errorf("not a constant %d", 3)},
		&VerificationFailure{fmt.Errorf("not a string %s", "i am a string")},
	} {
		t.Run(want.Error(), func(t *testing.T) {
			verr := &VerificationFailure{}
			if !errors.As(want, &verr) {
				t.Errorf("%v is not a %T", want, &VerificationFailure{})
			}

			// Check that Is sees it as the same error through multiple
			// levels of wrapping.
			wrapped := want
			for i := 0; i < 5; i++ {
				if !errors.Is(wrapped, want) {
					t.Errorf("%v is not %v", wrapped, want)
				}
				wrapped = fmt.Errorf("wrapper: %w", wrapped)
			}
		})
	}
}
