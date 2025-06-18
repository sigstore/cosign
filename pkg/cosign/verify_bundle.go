//
// Copyright 2025 The Sigstore Authors.
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

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyNewBundle verifies a SigstoreBundle with the given parameters
func VerifyNewBundle(_ context.Context, co *CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, bundle verify.SignedEntity) (*verify.VerificationResult, error) {
	trustedMaterial, verifierOptions, policyOptions, err := co.verificationOptions()
	if err != nil {
		return nil, err
	}
	verifier, err := verify.NewVerifier(trustedMaterial, verifierOptions...)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(bundle, verify.NewPolicy(artifactPolicyOption, policyOptions...))
}
