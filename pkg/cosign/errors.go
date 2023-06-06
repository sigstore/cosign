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

// VerificationFailure is the type of Go error that is used by cosign to surface
// errors actually related to verification (vs. transient, misconfiguration,
// transport, or authentication related issues).
// It is now marked as deprecated and will be removed in favour of defined
// error types with use of the ThrowError function.
type VerificationFailure struct {
	err error
}

// ThrowError returns the error type that is passed. It acts as a
// single consistent way of throwing errors from the pkg level.
// As long as the error type is defined before hand, this can be
// used to throw errors up to the calling code without discrimination
// around the error type.
func ThrowError(err interface{ error }) error {
	return err
}

func (e *VerificationFailure) Error() string {
	return e.err.Error()
}

type ErrNoMatchingSignatures struct {
	err error
}

func (e *ErrNoMatchingSignatures) Error() string {
	return e.err.Error()
}

type ErrImageTagNotFound struct {
	err error
}

func (e *ErrImageTagNotFound) Error() string {
	return e.err.Error()
}

type ErrNoSignaturesFound struct {
	err error
}

func (e *ErrNoSignaturesFound) Error() string {
	return e.err.Error()
}

type ErrNoMatchingAttestations struct {
	err error
}

func (e *ErrNoMatchingAttestations) Error() string {
	return e.err.Error()
}
