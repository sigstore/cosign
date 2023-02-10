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
	verificationError "github.com/sigstore/cosign/v2/pkg/cosign"
)

// exitCodeLookup contains a map of errorTypes and their associated exitCodes.
var exitCodeLookup = map[string]int{
	verificationError.ErrNoMatchingSignaturesType: NoMatchingSignature,
}

func LookupExitCodeForErrorType(errorType string) int {
	exitCode := exitCodeLookup[errorType]

	// if there is no entry in the lookup map for the passed errorType,
	// then by default, it will return `0`. however, as `0` as an exitCode
	// for success, we want to return `1` instead until there is a valid
	// exit code entry in the map for the passed errorType.
	if exitCode == 0 {
		return 1
	}
	return exitCode
}
