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

// VerifyNewBundle verifies a Sigstore bundle with the given parameters
func VerifyNewBundle(_ context.Context, co *CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, bundle verify.SignedEntity) (*verify.VerificationResult, error) {
	if err := rekorV2Bundle(bundle, co); err != nil {
		return nil, err
	}
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

// rekorV2Bundle checks if a bundle contains only Rekor v2 entries, and if so, mandates that
// a signed timestamp is provided when verifying a certificate. Unlike Rekor v1, Rekor v2 does
// not provide timestamps, and so when verifying a short-lived certificates, users either explicitly
// need to specify --use-signed-timestamps, or we'll opportunistically set it here.
// This check does nothing if users skip transparency log verification or provide a key, since
// a trusted timestamp is unneeded.
// If a bundle were to contain both a Rekor v1 and Rekor v2 entry, but with trust material that
// will only successfully verify the Rekor v1 entry, this would cause a verification failure.
// Therefore, if we have a mixed bundle, we will do nothing and require that the user explicitly
// opt in to checking for signed timestamps.
// There is one edge case that isn't handled - A bundle with a Rekor v2 entry with a certificate
// that should be validated using the current time rather than a provided timestamp. If someone runs
// into this, we can add a flag like --use-current-time.
func rekorV2Bundle(bundle verify.SignedEntity, co *CheckOpts) error {
	// Without a transparency log entry, users will need to opt in to verifying timestamps.
	// With a key, there's no need for timestamps.
	if co.IgnoreTlog || co.SigVerifier != nil {
		return nil
	}
	logEntries, err := bundle.TlogEntries()
	if err != nil {
		return err
	}
	var hasRekorV1, hasRekorV2 bool
	for _, logEntry := range logEntries {
		// Rekor v2 entries do not specify an integrated time
		if logEntry.IntegratedTime().IsZero() {
			hasRekorV2 = true
		} else {
			hasRekorV1 = true
		}
	}
	if hasRekorV2 && !hasRekorV1 {
		co.UseSignedTimestamps = true
	}
	return nil
}
