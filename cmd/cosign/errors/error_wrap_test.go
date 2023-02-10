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

package errors

import (
	"errors"
	"testing"

	verificationError "github.com/sigstore/cosign/v2/pkg/cosign"
)

func TestWrapWithVerificationError(t *testing.T) {
	ve := &verificationError.VerificationError{}
	ve.SetErrorType(verificationError.ErrNoMatchingSignaturesType)
	err := WrapError(ve)

	var cosignError *CosignError
	if errors.As(err, &cosignError) {
		if cosignError.ExitCode() != NoMatchingSignature {
			t.Fatalf("verification error unsuccessfully wrapped")
		}
		t.Logf("verification error successfully wrapped and exit code returned")
	}
}

func TestWrapWithGenericCosignError(t *testing.T) {
	errorText := "i am a generic cosign error"
	err := WrapError(errors.New(errorText))

	var cosignError *CosignError
	if errors.As(err, &cosignError) {
		if cosignError.ExitCode() == 1 && cosignError.Message == errorText {
			t.Logf("generic cosign error successfully returned")
			return
		}
		t.Fatalf("generic cosign error unsuccessfully returned")
	}
}
