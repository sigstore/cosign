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

import "fmt"

// VerificationFailure is the type of Go error that is used by cosign to surface
// errors actually related to verification (vs. transient, misconfiguration,
// transport, or authentication related issues).
type VerificationFailure struct {
	err error
}

func (e *VerificationFailure) Error() string {
	return e.err.Error()
}

func (e *VerificationFailure) Unwrap() error {
	return e.err
}

type ErrNoMatchingSignatures struct {
	err error
}

func (e *ErrNoMatchingSignatures) Error() string {
	return e.err.Error()
}

func (e *ErrNoMatchingSignatures) Unwrap() error {
	return e.err
}

type ErrImageTagNotFound struct {
	err error
}

func (e *ErrImageTagNotFound) Error() string {
	return e.err.Error()
}

func (e *ErrImageTagNotFound) Unwrap() error {
	return e.err
}

type ErrNoSignaturesFound struct {
	err error
}

func (e *ErrNoSignaturesFound) Error() string {
	return e.err.Error()
}

func (e *ErrNoSignaturesFound) Unwrap() error {
	return e.err
}

type ErrNoMatchingAttestations struct {
	err error
}

func (e *ErrNoMatchingAttestations) Error() string {
	return e.err.Error()
}

func (e *ErrNoMatchingAttestations) Unwrap() error {
	return e.err
}

type ErrNoCertificateFoundOnSignature struct {
	err error
}

func (e *ErrNoCertificateFoundOnSignature) Error() string {
	return e.err.Error()
}

func (e *ErrNoCertificateFoundOnSignature) Unwrap() error {
	return e.err
}

// NewVerificationError exists for backwards compatibility.
// Deprecated: see [VerificationFailure].
func NewVerificationError(msg string, args ...interface{}) error {
	return &VerificationError{
		message: fmt.Sprintf(msg, args...),
	}
}

// VerificationError exists for backwards compatibility.
// Deprecated: see [VerificationFailure].
type VerificationError struct {
	message string
}

func (e *VerificationError) Error() string {
	return e.message
}

var (
	// ErrNoMatchingAttestationsMessage exists for backwards compatibility.
	// Deprecated: see [ErrNoMatchingAttestations].
	ErrNoMatchingAttestationsMessage = "no matching attestations"

	// ErrNoMatchingAttestationsType exists for backwards compatibility.
	// Deprecated: see [ErrNoMatchingAttestations].
	ErrNoMatchingAttestationsType = "NoMatchingAttestations"
)
