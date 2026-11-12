// Copyright 2026 The Sigstore Authors.
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

package signcommon

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// ErrAlreadySigned is returned by NewAttestationBundle when CommonBundleOpts.SkipIfSigned is set and the
// digest already has a verified bundle of the same predicate type from the identity that would sign it.
var ErrAlreadySigned = errors.New("already signed by this identity")

// signedBySigner reports whether the digest already has a bundle of bundleOpts.PredicateType that
// verifies against the trusted material and the identity keypair signs as.
// A failed lookup is reported as not signed, so the caller signs rather than silently skipping.
func signedBySigner(ctx context.Context, keypair sign.Keypair, idToken string, bundleOpts CommonBundleOpts,
	signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial, signOpts *cbundle.SignOptions) (bool, error) {
	co, certProvider, err := signerCheckOpts(ctx, keypair, idToken, signingConfig, trustedMaterial)
	if err != nil {
		return false, err
	}
	// The signature that follows must use the certificate the existing bundles were checked against.
	if certProvider != nil {
		signOpts.CertificateProvider = certProvider
	}
	co.RegistryClientOpts = bundleOpts.OCIRemoteOpts
	co.IgnoreTlog = len(signingConfig.RekorLogURLs()) == 0
	// Without a log, an expired Fulcio certificate verifies only against a signed timestamp.
	co.UseSignedTimestamps = co.IgnoreTlog && co.SigVerifier == nil && len(signingConfig.TimestampAuthorityURLs()) > 0

	bundles, hash, err := cosign.GetBundles(ctx, bundleOpts.Digest, bundleOpts.OCIRemoteOpts)
	var noBundles *cosign.ErrNoMatchingAttestations
	if errors.As(err, &noBundles) {
		return false, nil
	}
	if err != nil {
		ui.Warnf(ctx, "checking %s for existing signatures, signing anyway: %v", bundleOpts.Digest, err)
		return false, nil
	}
	digest, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return false, err
	}
	artifactPolicy := verify.WithArtifactDigest(hash.Algorithm, digest)

	for _, b := range bundles {
		res, err := cosign.VerifyNewBundle(ctx, co, artifactPolicy, b)
		if err == nil && res.Statement.GetPredicateType() == bundleOpts.PredicateType {
			return true, nil
		}
	}
	return false, nil
}

// signerCheckOpts returns CheckOpts that accept only bundles signed as keypair's identity:
// the Fulcio certificate's SAN and OIDC issuer when signing keyless, otherwise the key itself.
// When keyless, it also returns the caching provider holding that certificate.
func signerCheckOpts(ctx context.Context, keypair sign.Keypair, idToken string,
	signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial) (*cosign.CheckOpts, sign.CertificateProvider, error) {
	co := &cosign.CheckOpts{TrustedMaterial: trustedMaterial}

	if idToken == "" {
		verifier, err := signature.LoadVerifier(keypair.GetPublicKey(), ProtoHashAlgoToHash(keypair.GetHashAlgorithm()))
		if err != nil {
			return nil, nil, fmt.Errorf("loading verifier: %w", err)
		}
		co.SigVerifier = verifier
		return co, nil, nil
	}

	provider, err := cbundle.NewCachingFulcioProvider(signingConfig)
	if err != nil {
		return nil, nil, err
	}
	der, err := provider.GetCertificate(ctx, keypair, &sign.CertificateProviderOptions{IDToken: idToken})
	if err != nil {
		return nil, nil, fmt.Errorf("getting signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing certificate: %w", err)
	}

	sans := cryptoutils.GetSubjectAlternateNames(cert)
	ext, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing signing certificate extensions: %w", err)
	}
	if len(sans) == 0 || ext.Issuer == "" {
		return nil, nil, errors.New("signing certificate has no subject alternative name or OIDC issuer")
	}
	co.Identities = []cosign.Identity{{Subject: sans[0], Issuer: ext.Issuer}}
	return co, provider, nil
}
