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

package types

const (
	// The signature is base64-encoded and stored as an annotation on the
	// layer, in the same descriptor.
	SignatureAnnotationKey = "dev.cosignproject.cosign/signature"
	// The certificate is stored as an annotation on the layer, in the same
	// descriptor.
	CertificateAnnotationKey = "dev.sigstore.cosign/certificate"
	// The chain is stored as an annotation on the layer, in the same descriptor.
	ChainAnnotationKey = "dev.sigstore.cosign/chain"
	// Contains a JSON formatted bundle type, which can be used for offline
	// verification.
	BundleAnnotationKey = "dev.sigstore.cosign/bundle"
)
