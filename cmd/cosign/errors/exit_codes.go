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

// Exit codes for cosign.
// To allow for document generation of exit codes the following convention is
// to be followed.
// Convention:
//   | // comment that explains the error
//   | const NamedConstant = ERRORCODE
//
// This is so when `make docgen` is run, the cosign_exit-codes.md doc is automatically
// generated inside of the docs dir following the format of "Exit Code : Comment".

// Error verifying image due to no signature
const ImageWithoutSignature = 10

// Error verifying image due to non-existent tag
const NonExistentTag = 11

// Error verifying image due to no matching signature
const NoMatchingSignature = 12

// Error verifying image due to no certificate found on signature
const NoCertificateFoundOnSignature = 13
