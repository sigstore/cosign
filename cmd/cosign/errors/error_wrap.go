//
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

package errors

import (
	"errors"

	verificationError "github.com/sigstore/cosign/v2/pkg/cosign"
)

// WrapError takes an error type and depending on the type of error
// passed, will access it's error message and errorType (and return
// the associated exitCode) and wrap them in a generic `CosignError`.
// If no custom error has been found, then it will still return a
// `CosignError` with an error message, but the `exitCode` will be `1`.
func WrapError(err error) error {
	// VerificationError
	var verificationError *verificationError.VerificationError
	if errors.As(err, &verificationError) {
		return &CosignError{
			Message: verificationError.Error(),
			Code:    LookupExitCodeForErrorType(verificationError.ErrorType()),
		}
	}

	// return default cosign error with error message and default exit code
	return &CosignError{
		Message: err.Error(),
		Code:    1,
	}
}
