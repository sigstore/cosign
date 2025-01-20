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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/tle"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
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

func checkNewBundle(bundlePath string) bool {
	_, err := sgbundle.LoadJSONFromPath(bundlePath)
	return err == nil
}

func verifyNewBundle(ctx context.Context, bundlePath, trustedRootPath, keyRef, slot, certOIDCIssuer, certOIDCIssuerRegex, certIdentity, certIdentityRegexp, githubWorkflowTrigger, githubWorkflowSHA, githubWorkflowName, githubWorkflowRepository, githubWorkflowRef, artifactRef string, sk, ignoreTlog, useSignedTimestamps, ignoreSCT bool) (*verify.VerificationResult, error) {
	bundle, err := sgbundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, err
	}

	var trustedroot *root.TrustedRoot

	if trustedRootPath == "" {
		ui.Infof(ctx, "no --trusted-root specified; fetching public good instance verification material via TUF")
		// Assume we're using public good instance; fetch via TUF
		trustedroot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, err
		}
	} else {
		trustedroot, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return nil, err
		}
	}

	trustedmaterial := &verifyTrustedMaterial{TrustedMaterial: trustedroot}

	// See if we need to wrap trusted root with provided key
	if keyRef != "" {
		signatureVerifier, err := sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return nil, err
		}

		newExpiringKey := root.NewExpiringKey(signatureVerifier, time.Time{}, time.Time{})
		trustedmaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	} else if sk {
		s, err := pivkey.GetKeyWithSlot(slot)
		if err != nil {
			return nil, fmt.Errorf("opening piv token: %w", err)
		}
		defer s.Close()
		signatureVerifier, err := s.Verifier()
		if err != nil {
			return nil, fmt.Errorf("loading public key from token: %w", err)
		}

		newExpiringKey := root.NewExpiringKey(signatureVerifier, time.Time{}, time.Time{})
		trustedmaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	}

	identityPolicies := []verify.PolicyOption{}

	verificationMaterial := bundle.GetVerificationMaterial()

	if verificationMaterial == nil {
		return nil, fmt.Errorf("no verification material in bundle")
	}

	if verificationMaterial.GetPublicKey() != nil {
		identityPolicies = append(identityPolicies, verify.WithKey())
	} else {
		sanMatcher, err := verify.NewSANMatcher(certIdentity, certIdentityRegexp)
		if err != nil {
			return nil, err
		}

		issuerMatcher, err := verify.NewIssuerMatcher(certOIDCIssuer, certOIDCIssuerRegex)
		if err != nil {
			return nil, err
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
			return nil, err
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
		verifierConfig = append(verifierConfig, verify.WithCurrentTime())
	}

	// Check if artifactRef is a digest or a file path
	var artifactOpt verify.ArtifactPolicyOption
	if _, err := os.Stat(artifactRef); err != nil {
		hexAlg, hexDigest, ok := strings.Cut(artifactRef, ":")
		if !ok {
			return nil, err
		}
		digestBytes, err := hex.DecodeString(hexDigest)
		if err != nil {
			return nil, err
		}
		artifactOpt = verify.WithArtifactDigest(hexAlg, digestBytes)
	} else {
		// Perform verification
		payload, err := payloadBytes(artifactRef)
		if err != nil {
			return nil, err
		}
		artifactOpt = verify.WithArtifact(bytes.NewBuffer(payload))
	}

	sev, err := verify.NewSignedEntityVerifier(trustedmaterial, verifierConfig...)
	if err != nil {
		return nil, err
	}

	return sev.Verify(bundle, verify.NewPolicy(artifactOpt, identityPolicies...))
}

func AssembleNewBundle(ctx context.Context, sigBytes, signedTimestamp []byte, envelope *dsse.Envelope, artifactRef string, cert *x509.Certificate, ignoreTlog bool, sigVerifier signature.Verifier, pkOpts []signature.PublicKeyOption, rekorClient *client.Rekor) (*sgbundle.Bundle, error) {
	payload, err := payloadBytes(artifactRef)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(payload)
	digest := sha256.Sum256(buf.Bytes())

	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}

	if envelope != nil && len(envelope.Signatures) > 0 {
		sigDecode, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
		if err != nil {
			return nil, err
		}

		sig := &protodsse.Signature{
			Sig: sigDecode,
		}

		payloadDecode, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, err
		}

		pb.Content = &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payloadDecode,
				PayloadType: envelope.PayloadType,
				Signatures:  []*protodsse.Signature{sig},
			},
		}
	} else {
		pb.Content = &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sigBytes,
			},
		}
	}

	if cert != nil {
		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{
			Certificate: &protocommon.X509Certificate{
				RawBytes: cert.Raw,
			},
		}
	} else if sigVerifier != nil {
		pub, err := sigVerifier.PublicKey(pkOpts...)
		if err != nil {
			return nil, err
		}
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)

		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: base64.StdEncoding.EncodeToString(hashedBytes[:]),
			},
		}
	}

	if len(signedTimestamp) > 0 {
		ts := &protocommon.RFC3161SignedTimestamp{
			SignedTimestamp: signedTimestamp,
		}

		pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{ts},
		}
	}

	if !ignoreTlog {
		var pem []byte
		var err error
		if cert != nil {
			pem, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return nil, err
			}
		} else if sigVerifier != nil {
			pub, err := sigVerifier.PublicKey(pkOpts...)
			if err != nil {
				return nil, err
			}
			pem, err = cryptoutils.MarshalPublicKeyToPEM(pub)
			if err != nil {
				return nil, err
			}
		}
		var sigB64 string
		var payload []byte
		if envelope != nil && len(envelope.Signatures) > 0 {
			payload, err = json.Marshal(*envelope)
			if err != nil {
				return nil, err
			}
		} else {
			sigB64 = base64.StdEncoding.EncodeToString(sigBytes)
			payload = buf.Bytes()
		}

		tlogEntries, err := cosign.FindTlogEntry(ctx, rekorClient, sigB64, payload, pem)
		if err != nil {
			return nil, err
		}
		if len(tlogEntries) == 0 {
			return nil, fmt.Errorf("unable to find tlog entry")
		}
		if len(tlogEntries) > 1 {
			return nil, fmt.Errorf("too many tlog entries; should only have 1")
		}

		tlogEntry, err := tle.GenerateTransparencyLogEntry(tlogEntries[0])
		if err != nil {
			return nil, err
		}

		pb.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{tlogEntry}
	}

	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		return nil, err
	}

	return b, nil
}
