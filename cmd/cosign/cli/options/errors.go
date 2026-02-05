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

package options

// KeyParseError is an error returned when an incorrect set of key flags
// are parsed by the CLI
type KeyParseError struct{}

// PubKeyParseError is an error returned when an incorrect set of public key
// flags are parsed by the CLI
type PubKeyParseError struct{}

// KeyAndIdentityParseError is an error returned when both
// key and identity flags are parsed by the CLI
type KeyAndIdentityParseError struct{}

func (e *KeyParseError) Error() string {
	return "exactly one of: key reference (--key), or hardware token (--sk) must be provided"
}

func (e *PubKeyParseError) Error() string {
	return "exactly one of: key reference (--key), certificate (--cert) or hardware token (--sk) must be provided"
}

func (e *KeyAndIdentityParseError) Error() string {
	return "exactly one of: key reference (--key) or certificate identity " +
		"(--certificate-identity or --certificate-identity-regexp), must be provided. " +
		"To determine which to use, inspect the bundle's 'verificationMaterial' field: " +
		"if 'publicKey' is present, use key reference; if 'certificate' or 'x509CertificateChain' is present, use certificate identity"
}
