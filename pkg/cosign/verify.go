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

package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ggcrlayout "github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/nozzle/throttler"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/ui"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekor_types "github.com/sigstore/rekor/pkg/types"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tuf"
	tsaverification "github.com/sigstore/timestamp-authority/v2/pkg/verification"
)

// Identity specifies an issuer/subject to verify a signature against.
// Both IssuerRegExp/SubjectRegExp support regexp while Issuer/Subject are for
// strict matching.
type Identity struct {
	Issuer        string
	Subject       string
	IssuerRegExp  string
	SubjectRegExp string
}

// CheckOpts are the options for checking signatures.
type CheckOpts struct {
	// RegistryClientOpts are the options for interacting with the container registry.
	RegistryClientOpts []ociremote.Option

	// Annotations optionally specifies image signature annotations to verify.
	Annotations map[string]interface{}

	// ClaimVerifier, if provided, verifies claims present in the oci.Signature.
	ClaimVerifier func(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error

	// TrustedMaterial contains trusted metadata for all Sigstore services. It is exclusive with RekorPubKeys, RootCerts, IntermediateCerts, CTLogPubKeys, and the TSA* cert fields.
	TrustedMaterial root.TrustedMaterial

	// RekorClient, if set, is used to make online tlog calls use to verify signatures and public keys.
	RekorClient *client.Rekor
	// RekorPubKeys, if set, is used to validate signatures on log entries from
	// Rekor. It is a map from LogID to crypto.PublicKey. LogID is
	// derived from the PublicKey (see RFC 6962 S3.2).
	// Note that even though the type is of crypto.PublicKey, Rekor only allows
	// for ecdsa.PublicKey: https://github.com/sigstore/cosign/issues/2540
	RekorPubKeys *TrustedTransparencyLogPubKeys

	// SigVerifier is used to verify signatures.
	SigVerifier signature.Verifier
	// PKOpts are the options provided to `SigVerifier.PublicKey()`.
	PKOpts []signature.PublicKeyOption

	// CertGithubWorkflowTrigger is the GitHub Workflow Trigger name expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertGithubWorkflowTrigger string
	// CertGithubWorkflowSha is the GitHub Workflow SHA expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertGithubWorkflowSha string
	// CertGithubWorkflowName is the GitHub Workflow Name expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertGithubWorkflowName string
	// CertGithubWorkflowRepository is the GitHub Workflow Repository  expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertGithubWorkflowRepository string
	// CertGithubWorkflowRef is the GitHub Workflow Ref expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertGithubWorkflowRef string

	// IgnoreSCT requires that a certificate contain an embedded SCT during verification. An SCT is proof of inclusion in a
	// certificate transparency log.
	IgnoreSCT bool
	// Detached SCT. Optional, as the SCT is usually embedded in the certificate.
	SCT []byte

	// SignatureRef is the reference to the signature file. PayloadRef should always be specified as well (though it’s possible for a _some_ signatures to be verified without it, with a warning).
	SignatureRef string
	// PayloadRef is a reference to the payload file. Applicable only if SignatureRef is set.
	PayloadRef string

	// Identities is an array of Identity (Subject, Issuer) matchers that have
	// to be met for the signature to ve valid.
	Identities []Identity

	// Force offline verification of the signature
	Offline bool

	// Set of flags to verify an RFC3161 timestamp used for trusted timestamping
	// TSACertificate is the certificate used to sign the timestamp. Optional, if provided in the timestamp
	TSACertificate *x509.Certificate
	// TSARootCertificates are the set of roots to verify the TSA certificate
	TSARootCertificates []*x509.Certificate
	// TSAIntermediateCertificates are the set of intermediates for chain building
	TSAIntermediateCertificates []*x509.Certificate
	// UseSignedTimestamps enables timestamp verification using a TSA
	UseSignedTimestamps bool

	// IgnoreTlog skip tlog verification
	IgnoreTlog bool

	// The amount of maximum workers for parallel executions.
	// Defaults to 10.
	MaxWorkers int

	// Should the experimental OCI 1.1 behaviour be enabled or not.
	// Defaults to false.
	ExperimentalOCI11 bool
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	if v.keyTrustedMaterial != nil {
		return v.keyTrustedMaterial.PublicKeyVerifier(hint)
	}
	if v.TrustedMaterial != nil {
		return v.TrustedMaterial.PublicKeyVerifier(hint)
	}
	return nil, fmt.Errorf("no public key material available")
}

// verificationOptions returns the verification options for verifying with sigstore-go.
func (co *CheckOpts) verificationOptions() (trustedMaterial root.TrustedMaterial, verifierOptions []verify.VerifierOption, policyOptions []verify.PolicyOption, err error) {
	if co.TrustedMaterial == nil && co.SigVerifier == nil {
		return nil, nil, nil, fmt.Errorf("a trusted root is required for identity-based verification")
	}

	policyOptions = make([]verify.PolicyOption, 0)

	if len(co.Identities) > 0 {
		var sanMatcher verify.SubjectAlternativeNameMatcher
		var issuerMatcher verify.IssuerMatcher
		if len(co.Identities) > 1 {
			return nil, nil, nil, fmt.Errorf("unsupported: multiple identities are not supported at this time")
		}
		sanMatcher, err = verify.NewSANMatcher(co.Identities[0].Subject, co.Identities[0].SubjectRegExp)
		if err != nil {
			return nil, nil, nil, err
		}

		issuerMatcher, err = verify.NewIssuerMatcher(co.Identities[0].Issuer, co.Identities[0].IssuerRegExp)
		if err != nil {
			return nil, nil, nil, err
		}

		extensions := certificate.Extensions{
			GithubWorkflowTrigger:    co.CertGithubWorkflowTrigger,
			GithubWorkflowSHA:        co.CertGithubWorkflowSha,
			GithubWorkflowName:       co.CertGithubWorkflowName,
			GithubWorkflowRepository: co.CertGithubWorkflowRepository,
			GithubWorkflowRef:        co.CertGithubWorkflowRef,
		}

		certificateIdentities, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
		if err != nil {
			return nil, nil, nil, err
		}
		policyOptions = []verify.PolicyOption{verify.WithCertificateIdentity(certificateIdentities)}
	}

	// Wrap TrustedMaterial
	vTrustedMaterial := &verifyTrustedMaterial{TrustedMaterial: co.TrustedMaterial}

	verifierOptions = make([]verify.VerifierOption, 0)

	if co.SigVerifier != nil {
		// We are verifying with a public key
		policyOptions = append(policyOptions, verify.WithKey())
		newExpiringKey := root.NewExpiringKey(co.SigVerifier, time.Time{}, time.Time{})
		vTrustedMaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	} else { //nolint:gocritic
		// We are verifying with a certificate
		if !co.IgnoreSCT {
			verifierOptions = append(verifierOptions, verify.WithSignedCertificateTimestamps(1))
		}
	}

	if !co.IgnoreTlog {
		verifierOptions = append(verifierOptions, verify.WithTransparencyLog(1))
		// If you aren't using a signed timestamp, use the time from the transparency log
		// to verify Fulcio certificates, or require no timestamp to verify a key.
		// For Rekor v2, a signed timestamp must be provided.
		if !co.UseSignedTimestamps {
			if co.SigVerifier == nil {
				verifierOptions = append(verifierOptions, verify.WithIntegratedTimestamps(1))
			} else {
				verifierOptions = append(verifierOptions, verify.WithNoObserverTimestamps())
			}
		}
	}
	if co.UseSignedTimestamps {
		verifierOptions = append(verifierOptions, verify.WithSignedTimestamps(1))
	}
	// A time verification policy must be provided. Without a signed timestamp or integrated timestamp,
	// verify a certificate with the current time, or require no timestamp to verify a key.
	if co.IgnoreTlog && !co.UseSignedTimestamps {
		if co.SigVerifier == nil {
			verifierOptions = append(verifierOptions, verify.WithCurrentTime())
		} else {
			verifierOptions = append(verifierOptions, verify.WithNoObserverTimestamps())
		}
	}

	return vTrustedMaterial, verifierOptions, policyOptions, nil
}

// CheckCertificatePolicy checks that the certificate subject and issuer match
// the expected values.
func CheckCertificatePolicy(cert *x509.Certificate, co *CheckOpts) error {
	ce := CertExtensions{Cert: cert}

	if err := validateCertExtensions(ce, co); err != nil {
		return err
	}
	oidcIssuer := ce.GetIssuer()
	sans := cryptoutils.GetSubjectAlternateNames(cert)
	// If there are identities given, go through them and if one of them
	// matches, call that good, otherwise, return an error.
	if len(co.Identities) > 0 {
		for _, identity := range co.Identities {
			issuerMatches := false
			switch {
			// Check the issuer first
			case identity.IssuerRegExp != "":
				if regex, err := regexp.Compile(identity.IssuerRegExp); err != nil {
					return fmt.Errorf("malformed issuer in identity: %s : %w", identity.IssuerRegExp, err)
				} else if regex.MatchString(oidcIssuer) {
					issuerMatches = true
				}
			case identity.Issuer != "":
				if identity.Issuer == oidcIssuer {
					issuerMatches = true
				}
			default:
				// No issuer constraint on this identity, so checks out
				issuerMatches = true
			}

			// Then the subject
			subjectMatches := false
			switch {
			case identity.SubjectRegExp != "":
				regex, err := regexp.Compile(identity.SubjectRegExp)
				if err != nil {
					return fmt.Errorf("malformed subject in identity: %s : %w", identity.SubjectRegExp, err)
				}
				for _, san := range sans {
					if regex.MatchString(san) {
						subjectMatches = true
						break
					}
				}
			case identity.Subject != "":
				for _, san := range sans {
					if san == identity.Subject {
						subjectMatches = true
						break
					}
				}
			default:
				// No subject constraint on this identity, so checks out
				subjectMatches = true
			}
			if subjectMatches && issuerMatches {
				// If both issuer / subject match, return verified
				return nil
			}
		}
		return &VerificationFailure{
			fmt.Errorf("none of the expected identities matched what was in the certificate, got subjects [%s] with issuer %s", strings.Join(sans, ", "), oidcIssuer),
		}
	}
	return nil
}

func validateCertExtensions(ce CertExtensions, co *CheckOpts) error {
	if co.CertGithubWorkflowTrigger != "" {
		if ce.GetCertExtensionGithubWorkflowTrigger() != co.CertGithubWorkflowTrigger {
			return &VerificationFailure{
				fmt.Errorf("expected GitHub Workflow Trigger not found in certificate"),
			}
		}
	}

	if co.CertGithubWorkflowSha != "" {
		if ce.GetExtensionGithubWorkflowSha() != co.CertGithubWorkflowSha {
			return &VerificationFailure{
				fmt.Errorf("expected GitHub Workflow SHA not found in certificate"),
			}
		}
	}

	if co.CertGithubWorkflowName != "" {
		if ce.GetCertExtensionGithubWorkflowName() != co.CertGithubWorkflowName {
			return &VerificationFailure{
				fmt.Errorf("expected GitHub Workflow Name not found in certificate"),
			}
		}
	}

	if co.CertGithubWorkflowRepository != "" {
		if ce.GetCertExtensionGithubWorkflowRepository() != co.CertGithubWorkflowRepository {
			return &VerificationFailure{
				fmt.Errorf("expected GitHub Workflow Repository not found in certificate"),
			}
		}
	}

	if co.CertGithubWorkflowRef != "" {
		if ce.GetCertExtensionGithubWorkflowRef() != co.CertGithubWorkflowRef {
			return &VerificationFailure{
				fmt.Errorf("expected GitHub Workflow Ref not found in certificate"),
			}
		}
	}
	return nil
}

func keyBytes(sig oci.Signature, co *CheckOpts) ([]byte, error) {
	cert, err := sig.Cert()
	if err != nil {
		return nil, err
	}
	var pub crypto.PublicKey
	if co.SigVerifier != nil {
		pub, err = co.SigVerifier.PublicKey(co.PKOpts...)
		if err != nil {
			return nil, err
		}
	}
	if cert != nil && co.SigVerifier != nil {
		if err := cryptoutils.EqualKeys(cert.PublicKey, pub); err != nil {
			return nil, fmt.Errorf("both public key and certificate were provided but did not match")
		}
	}

	if cert != nil {
		return cryptoutils.MarshalCertificateToPEM(cert)
	}
	return cryptoutils.MarshalPublicKeyToPEM(pub)
}

// VerifyImageAttestations does all the main cosign checks in a loop, returning the verified attestations.
// If there were no valid attestations, we return an error.
func VerifyImageAttestations(ctx context.Context, signedImgRef name.Reference, co *CheckOpts, nameOpts ...name.Option) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	bundles, hash, err := GetBundles(ctx, signedImgRef, co.RegistryClientOpts, nameOpts...)
	if err != nil {
		return nil, false, err
	}
	return verifyImageAttestationsSigstoreBundles(ctx, bundles, hash, co)
}

// VerifyLocalImageAttestations verifies attestations from a saved, local image, without any network calls,
// returning the verified attestations.
// If there were no valid signatures, we return an error.
func VerifyLocalImageAttestations(ctx context.Context, path string, co *CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	bundles, hash, err := GetLocalBundles(path)
	if err != nil {
		return nil, false, err
	}

	return verifyImageAttestationsSigstoreBundles(ctx, bundles, hash, co)
}

// CheckExpiry confirms the time provided is within the valid period of the certificate and optionally
// all issuing CA certificates.
func CheckExpiry(cert *x509.Certificate, issuingChain []*x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return &VerificationFailure{
			fmt.Errorf("certificate expired before observed time: %s is before %s",
				ft(cert.NotAfter), ft(it)),
		}
	}
	if cert.NotBefore.After(it) {
		return &VerificationFailure{
			fmt.Errorf("certificate was issued after observed time: %s is after %s",
				ft(cert.NotBefore), ft(it)),
		}
	}
	for _, c := range issuingChain {
		if c.NotAfter.Before(it) {
			return &VerificationFailure{
				fmt.Errorf("issuing CA certificate expired before observed time: %s is before %s",
					ft(c.NotAfter), ft(it)),
			}
		}
		if c.NotBefore.After(it) {
			return &VerificationFailure{
				fmt.Errorf("issuing CA certificate was issued after observed time: %s is after %s",
					ft(c.NotBefore), ft(it)),
			}
		}
	}
	return nil
}

// This verifies an offline bundle contained in the sig against the trusted
// Rekor publicKeys.
func VerifyBundle(sig oci.Signature, co *CheckOpts) (bool, error) {
	bundle, err := sig.Bundle()
	if err != nil {
		return false, err
	} else if bundle == nil {
		return false, nil
	}

	if co.TrustedMaterial == nil && (co.RekorPubKeys == nil || co.RekorPubKeys.Keys == nil) {
		return false, errors.New("no trusted rekor public keys provided")
	}

	bundleBody, ok := bundle.Payload.Body.(string)
	if !ok {
		return false, errors.New("bundle payload body is not a string")
	}

	if err := compareSigs(bundleBody, sig); err != nil {
		return false, err
	}

	if err := comparePublicKey(bundleBody, sig, co); err != nil {
		return false, err
	}

	payload, err := sig.Payload()
	if err != nil {
		return false, fmt.Errorf("reading payload: %w", err)
	}
	signature, err := sig.Base64Signature()
	if err != nil {
		return false, fmt.Errorf("reading base64signature: %w", err)
	}

	alg, bundlehash, err := bundleHash(bundleBody, signature)
	if err != nil {
		return false, fmt.Errorf("computing bundle hash: %w", err)
	}
	h := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(h[:])

	if alg != "sha256" {
		return false, fmt.Errorf("unexpected algorithm: %q", alg)
	} else if bundlehash != payloadHash {
		return false, fmt.Errorf("matching bundle to payload: bundle=%q, payload=%q", bundlehash, payloadHash)
	}

	if co.TrustedMaterial != nil {
		payload := bundle.Payload
		logID, err := hex.DecodeString(payload.LogID)
		if err != nil {
			return false, fmt.Errorf("decoding log ID: %w", err)
		}
		body, _ := base64.StdEncoding.DecodeString(bundleBody)
		entry, err := tlog.NewEntry(body, payload.IntegratedTime, payload.LogIndex, logID, bundle.SignedEntryTimestamp, nil)
		if err != nil {
			return false, fmt.Errorf("converting tlog entry: %w", err)
		}
		if err := tlog.VerifySET(entry, co.TrustedMaterial.RekorLogs()); err != nil {
			return false, fmt.Errorf("verifying bundle with trusted root: %w", err)
		}

		return true, nil
	}
	// Make sure all the rekorPubKeys are ecsda.PublicKeys
	for k, v := range co.RekorPubKeys.Keys {
		if _, ok := v.PubKey.(*ecdsa.PublicKey); !ok {
			return false, fmt.Errorf("rekor Public key for LogID %s is not type ecdsa.PublicKey", k)
		}
	}

	pubKey, ok := co.RekorPubKeys.Keys[bundle.Payload.LogID]
	if !ok {
		return false, &VerificationFailure{
			fmt.Errorf("verifying bundle: rekor log public key not found for payload"),
		}
	}
	err = VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, pubKey.PubKey.(*ecdsa.PublicKey))
	if err != nil {
		return false, err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	return true, nil
}

type signedEntityForTimestamp struct {
	verify.BaseSignedEntity
	timestamp  *cbundle.RFC3161Timestamp
	sigContent *sigContent
}

type sigContent struct {
	rawSig []byte
}

func (e *signedEntityForTimestamp) Timestamps() ([][]byte, error) {
	timestamps := make([][]byte, 1)
	timestamps[0] = e.timestamp.SignedRFC3161Timestamp
	return timestamps, nil
}

func (e *signedEntityForTimestamp) SignatureContent() (verify.SignatureContent, error) {
	return e.sigContent, nil
}

func (s *sigContent) Signature() []byte {
	return s.rawSig
}

func (s *sigContent) EnvelopeContent() verify.EnvelopeContent {
	log.Fatal("programmer error: EnvelopeContent was called but not implemented")
	return nil
}

func (s *sigContent) MessageSignatureContent() verify.MessageSignatureContent {
	log.Fatal("programmer error: MessageSignatureContent was called but not implemented")
	return nil
}

// VerifyRFC3161Timestamp verifies that the timestamp in sig is correctly signed, and if so,
// returns the timestamp value.
// It returns (nil, nil) if there is no timestamp, or (nil, err) if there is an invalid timestamp or if
// no root is provided with a timestamp.
//
// Note: This function does not perform CRL/OCSP certificate revocation checks.
// Callers are responsible for validating the TSA certificate and trusted material provided via CheckOpts according to their policy.
func VerifyRFC3161Timestamp(sig oci.Signature, co *CheckOpts) (*timestamp.Timestamp, error) {
	ts, err := sig.RFC3161Timestamp()
	switch {
	case err != nil:
		return nil, err
	case ts == nil:
		return nil, nil
	case co.TSARootCertificates == nil && co.TrustedMaterial == nil:
		return nil, errors.New("no TSA root certificate(s) provided to verify timestamp")
	}

	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, fmt.Errorf("reading base64signature: %w", err)
	}

	var tsBytes []byte
	if len(b64Sig) == 0 {
		// For attestations, the Base64Signature is not set, therefore we rely on the signed payload
		signedPayload, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("reading the payload: %w", err)
		}
		tsBytes = signedPayload
	} else {
		// create timestamp over raw bytes of signature
		rawSig, err := base64.StdEncoding.DecodeString(b64Sig)
		if err != nil {
			return nil, err
		}
		tsBytes = rawSig
	}

	if co.TrustedMaterial != nil {
		entity := &signedEntityForTimestamp{
			timestamp:  ts,
			sigContent: &sigContent{rawSig: tsBytes},
		}
		verifiedTimestamps, verifyErrs, err := verify.VerifySignedTimestamp(entity, co.TrustedMaterial)
		if err != nil {
			return nil, fmt.Errorf("unable to verify signed timestamps with trusted root: %w", err)
		}
		if len(verifyErrs) > 0 {
			log.Printf("Warning: subset of signed timestamps failed to verify: %v", verifyErrs)
		}
		if len(verifiedTimestamps) == 0 {
			return nil, fmt.Errorf("expected at least one verified timestamp")
		}
		return &timestamp.Timestamp{Time: verifiedTimestamps[0].Time}, nil
	}

	return tsaverification.VerifyTimestampResponse(ts.SignedRFC3161Timestamp, bytes.NewReader(tsBytes),
		tsaverification.VerifyOpts{
			TSACertificate: co.TSACertificate,
			Intermediates:  co.TSAIntermediateCertificates,
			Roots:          co.TSARootCertificates,
		})
}

// compare bundle signature to the signature we are verifying
func compareSigs(bundleBody string, sig oci.Signature) error {
	// TODO(nsmith5): modify function signature to make it more clear _why_
	// we've returned nil (there are several reasons possible here).
	actualSig, err := sig.Base64Signature()
	if err != nil {
		return fmt.Errorf("base64 signature: %w", err)
	}
	if actualSig == "" {
		// NB: empty sig means this is an attestation
		return nil
	}
	bundleSignature, err := bundleSig(bundleBody)
	if err != nil {
		return fmt.Errorf("failed to extract signature from bundle: %w", err)
	}
	if bundleSignature == "" {
		return nil
	}
	if bundleSignature != actualSig {
		return &VerificationFailure{
			fmt.Errorf("signature in bundle does not match signature being verified"),
		}
	}
	return nil
}

func comparePublicKey(bundleBody string, sig oci.Signature, co *CheckOpts) error {
	pemBytes, err := keyBytes(sig, co)
	if err != nil {
		return err
	}

	bundleKey, err := bundleKey(bundleBody)
	if err != nil {
		return fmt.Errorf("failed to extract key from bundle: %w", err)
	}

	decodeSecond, err := base64.StdEncoding.DecodeString(bundleKey)
	if err != nil {
		return fmt.Errorf("decoding base64 string %s", bundleKey)
	}

	// Compare the PEM bytes, to ignore spurious newlines in the public key bytes.
	pemFirst, rest := pem.Decode(pemBytes)
	if len(rest) > 0 {
		return fmt.Errorf("unexpected PEM block: %s", rest)
	}
	pemSecond, rest := pem.Decode(decodeSecond)
	if len(rest) > 0 {
		return fmt.Errorf("unexpected PEM block: %s", rest)
	}

	if !bytes.Equal(pemFirst.Bytes, pemSecond.Bytes) {
		return fmt.Errorf("comparing public key PEMs, expected %s, got %s",
			pemBytes, decodeSecond)
	}

	return nil
}

func extractEntryImpl(bundleBody string) (rekor_types.EntryImpl, error) {
	pe, err := models.UnmarshalProposedEntry(base64.NewDecoder(base64.StdEncoding, strings.NewReader(bundleBody)), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	return rekor_types.UnmarshalEntry(pe)
}

func bundleHash(bundleBody, _ string) (string, string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		return *entry.DSSEObj.EnvelopeHash.Algorithm, *entry.DSSEObj.EnvelopeHash.Value, nil
	case *hashedrekord_v001.V001Entry:
		return *entry.HashedRekordObj.Data.Hash.Algorithm, *entry.HashedRekordObj.Data.Hash.Value, nil
	case *intoto_v001.V001Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *intoto_v002.V002Entry:
		return *entry.IntotoObj.Content.Hash.Algorithm, *entry.IntotoObj.Content.Hash.Value, nil
	case *rekord_v001.V001Entry:
		return *entry.RekordObj.Data.Hash.Algorithm, *entry.RekordObj.Data.Hash.Value, nil
	default:
		return "", "", errors.New("unsupported type")
	}
}

// bundleSig extracts the signature from the rekor bundle body
func bundleSig(bundleBody string) (string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		if len(entry.DSSEObj.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return *entry.DSSEObj.Signatures[0].Signature, nil
	case *hashedrekord_v001.V001Entry:
		return entry.HashedRekordObj.Signature.Content.String(), nil
	case *intoto_v002.V002Entry:
		if len(entry.IntotoObj.Content.Envelope.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.IntotoObj.Content.Envelope.Signatures[0].Sig.String(), nil
	case *rekord_v001.V001Entry:
		return entry.RekordObj.Signature.Content.String(), nil
	default:
		return "", errors.New("unsupported type")
	}
}

// bundleKey extracts the key from the rekor bundle body
func bundleKey(bundleBody string) (string, error) {
	ei, err := extractEntryImpl(bundleBody)
	if err != nil {
		return "", err
	}

	switch entry := ei.(type) {
	case *dsse_v001.V001Entry:
		if len(entry.DSSEObj.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.DSSEObj.Signatures[0].Verifier.String(), nil
	case *hashedrekord_v001.V001Entry:
		return entry.HashedRekordObj.Signature.PublicKey.Content.String(), nil
	case *intoto_v001.V001Entry:
		return entry.IntotoObj.PublicKey.String(), nil
	case *intoto_v002.V002Entry:
		if len(entry.IntotoObj.Content.Envelope.Signatures) > 1 {
			return "", errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		return entry.IntotoObj.Content.Envelope.Signatures[0].PublicKey.String(), nil
	case *rekord_v001.V001Entry:
		return entry.RekordObj.Signature.PublicKey.Content.String(), nil
	default:
		return "", errors.New("unsupported type")
	}
}

func VerifySET(bundlePayload cbundle.RekorPayload, signature []byte, pub *ecdsa.PublicKey) error {
	contents, err := json.Marshal(bundlePayload)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalizing: %w", err)
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		return &VerificationFailure{
			fmt.Errorf("unable to verify SET"),
		}
	}
	return nil
}

func TrustedCert(cert *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime:   cert.NotBefore,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cert verification failed: %w. Check your TUF root (see cosign initialize) or set a custom root with env var SIGSTORE_ROOT_FILE", err)
	}
	return chains, nil
}

func correctAnnotations(wanted, have map[string]interface{}) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}

func GetBundles(_ context.Context, signedImgRef name.Reference, registryClientOpts []ociremote.Option, nameOpts ...name.Option) ([]*sgbundle.Bundle, *v1.Hash, error) {
	// This is a carefully optimized sequence for fetching the signatures of the
	// entity that minimizes registry requests when supplied with a digest input
	digest, err := ociremote.ResolveDigest(signedImgRef, registryClientOpts...)
	if err != nil {
		if terr := (&transport.Error{}); errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil, nil, &ErrImageTagNotFound{
				fmt.Errorf("image tag not found: %w", err),
			}
		}
		return nil, nil, err
	}
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, nil, err
	}

	index, err := ociremote.Referrers(digest, "", registryClientOpts...)
	if err != nil {
		return nil, nil, err
	}

	bundleRepo := digest.Repository
	if targetRepo := ociremote.TargetRepositoryFromOptions(registryClientOpts...); (targetRepo != name.Repository{}) {
		bundleRepo = targetRepo
	}

	var bundles = make([]*sgbundle.Bundle, 0, len(index.Manifests))
	for _, result := range index.Manifests {
		st, err := name.ParseReference(fmt.Sprintf("%s@%s", bundleRepo, result.Digest.String()), nameOpts...)
		if err != nil {
			return nil, nil, err
		}
		bundle, err := ociremote.Bundle(st, registryClientOpts...)
		if err != nil {
			// There may be non-Sigstore referrers in the index, so we can ignore them.
			// TODO: Should we surface any errors here (e.g. if the bundle is invalid)?
			continue
		}
		bundles = append(bundles, bundle)
	}

	if len(bundles) == 0 {
		return nil, nil, &ErrNoMatchingAttestations{
			fmt.Errorf("no valid bundles exist in registry"),
		}
	}

	return bundles, &h, nil
}

// bundleDescriptor holds the digest and path to a bundle blob in a local OCI layout
type bundleDescriptor struct {
	digest   v1.Hash
	blobPath string
}

// HasLocalBundles checks if a local OCI layout has v3 sigstore bundles.
// V3 bundles are stored as separate images with layers having
// media type "application/vnd.dev.sigstore.bundle".
func HasLocalBundles(path string) (bool, error) {
	return hasLocalSigstoreBundles(path)
}

// HasLocalAttestationBundles checks if a local OCI layout has v3 sigstore bundles for attestations.
// For v3, both signatures and attestations use the same bundle format.
func HasLocalAttestationBundles(path string) (bool, error) {
	return hasLocalSigstoreBundles(path)
}

// GetLocalBundles retrieves v3 sigstore bundles from a local OCI layout.
// Returns bundles, target image hash, and error. Invalid bundles are logged and skipped.
func GetLocalBundles(path string) ([]*sgbundle.Bundle, *v1.Hash, error) {
	descriptors, hash, err := getLocalBundleDescriptors(path)
	if err != nil {
		return nil, nil, err
	}

	bundles := make([]*sgbundle.Bundle, 0, len(descriptors))
	for _, descriptor := range descriptors {
		bundleBytes, err := os.ReadFile(filepath.Join(path, descriptor.blobPath))
		if err != nil {
			ui.Warnf(context.Background(), "Failed to read bundle blob %s: %v", descriptor.digest.Hex, err)
			continue
		}

		bundle := &sgbundle.Bundle{}
		if err := bundle.UnmarshalJSON(bundleBytes); err != nil {
			ui.Warnf(context.Background(), "Failed to unmarshal bundle %s: %v", descriptor.digest.Hex, err)
			continue
		}

		if !bundle.MinVersion("v0.3") {
			ui.Warnf(context.Background(), "Bundle %s version too old (requires v0.3+)", descriptor.digest.Hex)
			continue
		}

		bundles = append(bundles, bundle)
	}

	if len(bundles) == 0 {
		return nil, nil, &ErrNoMatchingAttestations{
			fmt.Errorf("no valid bundles found in local layout"),
		}
	}

	return bundles, hash, nil
}

func hasLocalSigstoreBundles(path string) (bool, error) {
	descriptors, _, err := getLocalBundleDescriptors(path)
	if err != nil {
		return false, err
	}
	return len(descriptors) > 0, nil
}

func getLocalBundleDescriptors(path string) ([]bundleDescriptor, *v1.Hash, error) {
	p, err := ggcrlayout.FromPath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("loading OCI layout from %s: %w", path, err)
	}

	ii, err := p.ImageIndex()
	if err != nil {
		return nil, nil, fmt.Errorf("getting image index: %w", err)
	}

	manifest, err := ii.IndexManifest()
	if err != nil {
		return nil, nil, fmt.Errorf("getting index manifest: %w", err)
	}

	// Find the target image digest from the index manifest
	var targetDigest v1.Hash
	for _, m := range manifest.Manifests {
		if val, ok := m.Annotations["kind"]; ok && (val == "dev.cosignproject.cosign/image" || val == "dev.cosignproject.cosign/imageIndex") {
			targetDigest = m.Digest
			break
		}
	}
	if targetDigest.String() == "" {
		return nil, nil, nil
	}

	// Scan blobs/sha256 directory for referrer manifests
	blobsDir := filepath.Join(path, "blobs", "sha256")
	entries, err := os.ReadDir(blobsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("reading blobs directory: %w", err)
	}

	var descriptors []bundleDescriptor
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		blobPath := filepath.Join(blobsDir, entry.Name())
		data, err := os.ReadFile(blobPath)
		if err != nil {
			continue
		}

		// Try to parse as manifest (skip blobs that aren't manifests)
		blobManifest, err := v1.ParseManifest(bytes.NewReader(data))
		if err != nil {
			continue
		}

		// Check if this is a referrer manifest pointing to our target
		if blobManifest.Subject != nil && blobManifest.Subject.Digest == targetDigest {
			// Collect bundle layer descriptors from this referrer manifest
			for _, layer := range blobManifest.Layers {
				if strings.HasPrefix(string(layer.MediaType), "application/vnd.dev.sigstore.bundle") {
					// layer.Digest.Hex is validated by go-containerregistry to be a valid hex hash,
					// but use filepath.Clean for defense-in-depth against path traversal
					descriptors = append(descriptors, bundleDescriptor{
						digest:   layer.Digest,
						blobPath: filepath.Clean(filepath.Join("blobs", "sha256", layer.Digest.Hex)),
					})
				}
			}
		}
	}

	return descriptors, &targetDigest, nil
}

// verifyImageAttestationsSigstoreBundles verifies attestations from attached sigstore bundles
func verifyImageAttestationsSigstoreBundles(ctx context.Context, bundles []*sgbundle.Bundle, hash *v1.Hash, co *CheckOpts) (checkedAttestations []oci.Signature, atLeastOneBundleVerified bool, err error) {
	// Enforce this up front.
	if co.SigVerifier == nil && co.TrustedMaterial == nil {
		return nil, false, errors.New("one of verifier or trusted root is required")
	}

	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return nil, false, err
	}

	artifactPolicyOption := verify.WithArtifactDigest(hash.Algorithm, digestBytes)

	attestations := make([]oci.Signature, len(bundles))
	bundlesVerified := make([]bool, len(bundles))

	workers := co.MaxWorkers
	if co.MaxWorkers == 0 {
		workers = cosign.DefaultMaxWorkers
	}
	t := throttler.New(workers, len(bundles))
	for i, bundle := range bundles {
		go func(bundle *sgbundle.Bundle, index int) {
			var att oci.Signature
			if err := func(bundle *sgbundle.Bundle) error {
				_, err := VerifyNewBundle(ctx, co, artifactPolicyOption, bundle)
				if err != nil {
					return err
				}
				dsse, ok := bundle.Content.(*protobundle.Bundle_DsseEnvelope)
				if !ok {
					return fmt.Errorf("bundle does not contain a DSSE envelope")
				}
				payload, err := json.Marshal(dsse.DsseEnvelope)
				if err != nil {
					return fmt.Errorf("marshaling DSSE envelope: %w", err)
				}

				// We will return a slice of `[]oci.Signature` from this function for compatibility
				// with the rest of the codebase. To do that, we wrap the verification output in a
				// `oci.Signature` using static.NewAttestation(). This type may contain additional
				// data such as the certificate chain, and rekor/tsa data, but for now we only use
				// the payload (DSSE). TODO: Add additional data to returned `oci.Signature`. This
				// can be done by passing a list of static.Option to NewAttestation (e.g. static.WithCertChain()).
				// Depends on https://github.com/sigstore/sigstore-go/issues/328
				att, err = static.NewAttestation(payload)
				if err != nil {
					return err
				}
				if co.ClaimVerifier != nil {
					if err := co.ClaimVerifier(att, *hash, co.Annotations); err != nil {
						return err
					}
				}
				bundlesVerified[index] = true

				return err
			}(bundle); err != nil {
				t.Done(err)
				return
			}

			attestations[index] = att
			t.Done(nil)
		}(bundle, i)

		// wait till workers are available
		t.Throttle()
	}

	for _, a := range attestations {
		if a != nil {
			checkedAttestations = append(checkedAttestations, a)
		}
	}

	for _, verified := range bundlesVerified {
		atLeastOneBundleVerified = atLeastOneBundleVerified || verified
	}

	if len(checkedAttestations) == 0 {
		return nil, false, &ErrNoMatchingAttestations{
			fmt.Errorf("no matching attestations: %w", errors.Join(t.Errs()...)),
		}
	}

	return checkedAttestations, atLeastOneBundleVerified, nil
}
