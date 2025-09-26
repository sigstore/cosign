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
	"fmt"
	"testing"

	pkgError "github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestDefaultExitCodeReturnIfErrorTypeToExitCodeMappingDoesNotExist(t *testing.T) {
	exitCode := LookupExitCodeForError(fmt.Errorf("I do not exist as an error type"))
	if exitCode != 1 {
		t.Fatalf("default exit code not returned when an error type doesn't exist. default should be 1")
	}
	t.Logf("Correct default exit code returned")
}

func TestDefaultExitCodeReturnIfErrorTypeToExitCodeMappingExists(t *testing.T) {
	// We test with any error that is not a generic CosignError.
	// In this case, ErrNoMatchingSignatures
	exitCode := LookupExitCodeForError(&pkgError.ErrNoMatchingSignatures{})
	if exitCode != NoMatchingSignature {
		t.Fatalf("NoMatchingSignature exit code not returned when error is thrown")
	}
	t.Logf("Correct default exit code returned")
}
