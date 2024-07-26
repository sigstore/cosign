//
// Copyright 2024 The Sigstore Authors.
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

package verify

import (
	"bytes"
	"context"
	"fmt"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}

func verifyNewBundle(ctx context.Context, bundlePath, trustedRootPath, keyRef, slot, certOIDCIssuer, certOIDCIssuerRegex, certIdentity, certIdentityRegexp, githubWorkflowTrigger, githubWorkflowSHA, githubWorkflowName, githubWorkflowRepository, githubWorkflowRef, artifactRef string, sk, ignoreTlog, useSignedTimestamps, ignoreSCT bool) error {
	bundle, err := sgbundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return err
	}

	var trustedroot *root.TrustedRoot

	if trustedRootPath == "" {
		// Assume we're using public good instance; fetch via TUF
		trustedroot, err = root.FetchTrustedRoot()
		if err != nil {
			return err
		}
	} else {
		trustedroot, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return err
		}
	}

	trustedmaterial := &verifyTrustedMaterial{TrustedMaterial: trustedroot}

	// See if we need to wrap trusted root with provided key
	if keyRef != "" {
		signatureVerifier, err := sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return err
		}

		newExpiringKey := root.NewExpiringKey(signatureVerifier, time.Time{}, time.Time{})
		trustedmaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	} else if sk {
		s, err := pivkey.GetKeyWithSlot(slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer s.Close()
		signatureVerifier, err := s.Verifier()
		if err != nil {
			return fmt.Errorf("loading public key from token: %w", err)
		}

		newExpiringKey := root.NewExpiringKey(signatureVerifier, time.Time{}, time.Time{})
		trustedmaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	}

	identityPolicies := []verify.PolicyOption{}

	verificationMaterial := bundle.GetVerificationMaterial()

	if verificationMaterial == nil {
		return fmt.Errorf("no verification material in bundle")
	}

	if verificationMaterial.GetPublicKey() != nil {
		identityPolicies = append(identityPolicies, verify.WithKey())
	} else {
		sanMatcher, err := verify.NewSANMatcher(certIdentity, certIdentityRegexp)
		if err != nil {
			return err
		}

		issuerMatcher, err := verify.NewIssuerMatcher(certOIDCIssuer, certOIDCIssuerRegex)
		if err != nil {
			return err
		}

		extensions := certificate.Extensions{
			GithubWorkflowTrigger:    githubWorkflowTrigger,
			GithubWorkflowSHA:        githubWorkflowSHA,
			GithubWorkflowName:       githubWorkflowName,
			GithubWorkflowRepository: githubWorkflowRepository,
			GithubWorkflowRef:        githubWorkflowRef,
		}

		certIdentity, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
		if err != nil {
			return err
		}

		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certIdentity))
	}

	// Make some educated guesses about verification policy
	verifierConfig := []verify.VerifierOption{}

	if len(trustedroot.RekorLogs()) > 0 && !ignoreTlog {
		verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	}

	if len(trustedroot.TimestampingAuthorities()) > 0 && useSignedTimestamps {
		verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))
	}

	if !ignoreSCT {
		verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))
	}

	if ignoreTlog && !useSignedTimestamps {
		verifierConfig = append(verifierConfig, verify.WithoutAnyObserverTimestampsUnsafe())
	}

	// Perform verification
	payload, err := payloadBytes(artifactRef)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(payload)

	sev, err := verify.NewSignedEntityVerifier(trustedmaterial, verifierConfig...)
	if err != nil {
		return err
	}

	_, err = sev.Verify(bundle, verify.NewPolicy(verify.WithArtifact(buf), identityPolicies...))
	return err
}
