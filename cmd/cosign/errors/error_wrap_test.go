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

package errors_test

import (
	stderrors "errors"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/errors"
)

func TestWrapWithGenericCosignError(t *testing.T) {
	errorText := "i am a generic cosign error"
	err := errors.WrapError(stderrors.New(errorText))

	var cosignError *errors.CosignError
	if stderrors.As(err, &cosignError) {
		if cosignError.ExitCode() == 1 && cosignError.Message == errorText {
			t.Logf("generic cosign error successfully returned")
			return
		}
		t.Fatalf("generic cosign error unsuccessfully returned")
	}
}
