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
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier/ctl"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/tuf"

	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/layout"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

// Identity specifies an issuer/subject to verify a signature against.
// Both Issuer/Subject support regexp.
type Identity struct {
	Issuer  string
	Subject string
}

// CheckOpts are the options for checking signatures.
type CheckOpts struct {
	// RegistryClientOpts are the options for interacting with the container registry.
	RegistryClientOpts []ociremote.Option

	// Annotations optionally specifies image signature annotations to verify.
	Annotations map[string]interface{}
	// ClaimVerifier, if provided, verifies claims present in the oci.Signature.
	ClaimVerifier func(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error

	// RekorClient, if set, is used to use to verify signatures and public keys.
	RekorClient *client.Rekor

	// SigVerifier is used to verify signatures.
	SigVerifier signature.Verifier
	// PKOpts are the options provided to `SigVerifier.PublicKey()`.
	PKOpts []signature.PublicKeyOption

	// RootCerts are the root CA certs used to verify a signature's chained certificate.
	RootCerts *x509.CertPool
	// IntermediateCerts are the optional intermediate CA certs used to verify a certificate chain.
	IntermediateCerts *x509.CertPool
	// CertEmail is the email expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertEmail string
	// CertOidcIssuer is the OIDC issuer expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertOidcIssuer string
	// EnforceSCT requires that a certificate contain an embedded SCT during verification. An SCT is proof of inclusion in a
	// certificate transparency log.
	EnforceSCT bool

	// SignatureRef is the reference to the signature file
	SignatureRef string

	// Identities is an array of Identity (Subject, Issuer) matchers that have
	// to be met for the signature to ve valid.
	// Supercedes CertEmail / CertOidcIssuer
	Identities []Identity
}

func getSignedEntity(signedImgRef name.Reference, regClientOpts []ociremote.Option) (oci.SignedEntity, v1.Hash, error) {
	se, err := ociremote.SignedEntity(signedImgRef, regClientOpts...)
	if err != nil {
		return nil, v1.Hash{}, err
	}
	// Both of the SignedEntity types implement Digest()
	h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
	if err != nil {
		return nil, v1.Hash{}, err
	}
	return se, h, nil
}

func verifyOCISignature(ctx context.Context, verifier signature.Verifier, sig oci.Signature) error {
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return err
	}
	payload, err := sig.Payload()
	if err != nil {
		return err
	}
	return verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))
}

// For unit testing
type payloader interface {
	Payload() ([]byte, error)
}

func verifyOCIAttestation(_ context.Context, verifier signature.Verifier, att payloader) error {
	payload, err := att.Payload()
	if err != nil {
		return err
	}

	env := ssldsse.Envelope{}
	if err := json.Unmarshal(payload, &env); err != nil {
		return err
	}

	if env.PayloadType != types.IntotoPayloadType {
		return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
	}
	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: verifier})
	if err != nil {
		return err
	}
	_, err = dssev.Verify(&env)
	return err
}

// ValidateAndUnpackCert creates a Verifier from a certificate. Veries that the certificate
// chains up to a trusted root. Optionally verifies the subject and issuer of the certificate.
func ValidateAndUnpackCert(cert *x509.Certificate, co *CheckOpts) (signature.Verifier, error) {
	verifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, errors.Wrap(err, "invalid certificate found on signature")
	}

	// Now verify the cert, then the signature.
	chains, err := TrustedCert(cert, co.RootCerts, co.IntermediateCerts)
	if err != nil {
		return nil, err
	}
	if co.CertEmail != "" {
		emailVerified := false
		for _, em := range cert.EmailAddresses {
			if co.CertEmail == em {
				emailVerified = true
				break
			}
		}
		if !emailVerified {
			return nil, errors.New("expected email not found in certificate")
		}
	}
	if co.CertOidcIssuer != "" {
		if getIssuer(cert) != co.CertOidcIssuer {
			return nil, errors.New("expected oidc issuer not found in certificate")
		}
	}
	// If there are identities given, go through them and if one of them
	// matches, call that good, otherwise, return an error.
	if len(co.Identities) > 0 {
		for _, identity := range co.Identities {
			issuerMatches := false
			// Check the issuer first
			if identity.Issuer != "" {
				issuer := getIssuer(cert)
				if regex, err := regexp.Compile(identity.Issuer); err != nil {
					return nil, fmt.Errorf("malformed issuer in identity: %s : %w", identity.Issuer, err)
				} else if regex.MatchString(issuer) {
					issuerMatches = true
				}
			} else {
				// No issuer constraint on this identity, so checks out
				issuerMatches = true
			}

			// Then the subject
			subjectMatches := false
			if identity.Subject != "" {
				regex, err := regexp.Compile(identity.Subject)
				if err != nil {
					return nil, fmt.Errorf("malformed subject in identity: %s : %w", identity.Subject, err)
				}
				for _, san := range getSubjectAlternateNames(cert) {
					if regex.MatchString(san) {
						subjectMatches = true
						break
					}
				}
			} else {
				// No subject constraint on this identity, so checks out
				subjectMatches = true
			}
			if subjectMatches && issuerMatches {
				// If both issuer / subject match, return verifier
				return verifier, nil
			}
		}
		return nil, errors.New("none of the expected identities matched what was in the certificate")
	}
	contains, err := ctl.ContainsSCT(cert.Raw)
	if err != nil {
		return nil, err
	}
	if co.EnforceSCT && !contains {
		return nil, errors.New("certificate does not include required embedded SCT")
	}
	if contains {
		// handle if chains has more than one chain - grab first and print message
		if len(chains) > 1 {
			fmt.Fprintf(os.Stderr, "**Info** Multiple valid certificate chains found. Selecting the first to verify the SCT.\n")
		}
		if err := ctl.VerifyEmbeddedSCT(context.Background(), chains[0]); err != nil {
			return nil, err
		}
	}
	return verifier, nil
}

// getSubjectAlternateNames returns all of the following for a Certificate.
// DNSNames
// EmailAddresses
// IPAddresses
// URIs
func getSubjectAlternateNames(cert *x509.Certificate) []string {
	sans := []string{}
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	return sans
}

// getIssuer returns the issuer for a Certificate
func getIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}) {
			return string(ext.Value)
		}
	}
	return ""
}

// ValidateAndUnpackCertWithChain creates a Verifier from a certificate. Verifies that the certificate
// chains up to the provided root. Chain should start with the parent of the certificate and end with the root.
// Optionally verifies the subject and issuer of the certificate.
func ValidateAndUnpackCertWithChain(cert *x509.Certificate, chain []*x509.Certificate, co *CheckOpts) (signature.Verifier, error) {
	if len(chain) == 0 {
		return nil, errors.New("no chain provided to validate certificate")
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[len(chain)-1])
	co.RootCerts = rootPool

	subPool := x509.NewCertPool()
	for _, c := range chain[:len(chain)-1] {
		subPool.AddCert(c)
	}
	co.IntermediateCerts = subPool

	return ValidateAndUnpackCert(cert, co)
}

func tlogValidatePublicKey(ctx context.Context, rekorClient *client.Rekor, pub crypto.PublicKey, sig oci.Signature) error {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	if err != nil {
		return err
	}
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return err
	}
	payload, err := sig.Payload()
	if err != nil {
		return err
	}
	_, err = FindTlogEntry(ctx, rekorClient, b64sig, payload, pemBytes)
	return err
}

func tlogValidateCertificate(ctx context.Context, rekorClient *client.Rekor, sig oci.Signature) error {
	cert, err := sig.Cert()
	if err != nil {
		return err
	}
	pemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return err
	}
	b64sig, err := sig.Base64Signature()
	if err != nil {
		return err
	}
	payload, err := sig.Payload()
	if err != nil {
		return err
	}
	e, err := FindTlogEntry(ctx, rekorClient, b64sig, payload, pemBytes)
	if err != nil {
		return err
	}
	if err := VerifyTLogEntry(ctx, rekorClient, e); err != nil {
		return err
	}
	// if we have a cert, we should check expiry
	return CheckExpiry(cert, time.Unix(*e.IntegratedTime, 0))
}

type fakeOCISignatures struct {
	oci.Signatures
	signatures []oci.Signature
}

func (fos *fakeOCISignatures) Get() ([]oci.Signature, error) {
	return fos.signatures, nil
}

// VerifyImageSignatures does all the main cosign checks in a loop, returning the verified signatures.
// If there were no valid signatures, we return an error.
func VerifyImageSignatures(ctx context.Context, signedImgRef name.Reference, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, false, errors.New("one of verifier or root certs is required")
	}

	// TODO(mattmoor): We could implement recursive verification if we just wrapped
	// most of the logic below here in a call to mutate.Map
	se, h, err := getSignedEntity(signedImgRef, co.RegistryClientOpts)
	if err != nil {
		return nil, false, err
	}

	var sigs oci.Signatures
	sigRef := co.SignatureRef
	if sigRef == "" {
		sigs, err = se.Signatures()
		if err != nil {
			return nil, false, err
		}
	} else {
		sigs, err = loadSignatureFromFile(sigRef, signedImgRef, co)
		if err != nil {
			return nil, false, err
		}
	}

	return verifySignatures(ctx, sigs, h, co)
}

// VerifyLocalImageSignatures verifies signatures from a saved, local image, without any network calls, returning the verified signatures.
// If there were no valid signatures, we return an error.
func VerifyLocalImageSignatures(ctx context.Context, path string, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, false, errors.New("one of verifier or root certs is required")
	}

	se, err := layout.SignedImageIndex(path)
	if err != nil {
		return nil, false, err
	}

	var h v1.Hash
	// Verify either an image index or image.
	ii, err := se.SignedImageIndex(v1.Hash{})
	if err != nil {
		return nil, false, err
	}
	i, err := se.SignedImage(v1.Hash{})
	if err != nil {
		return nil, false, err
	}
	switch {
	case ii != nil:
		h, err = ii.Digest()
		if err != nil {
			return nil, false, err
		}
	case i != nil:
		h, err = i.Digest()
		if err != nil {
			return nil, false, err
		}
	default:
		return nil, false, errors.New("must verify either an image index or image")
	}

	sigs, err := se.Signatures()
	if err != nil {
		return nil, false, err
	}

	return verifySignatures(ctx, sigs, h, co)
}

func verifySignatures(ctx context.Context, sigs oci.Signatures, h v1.Hash, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	sl, err := sigs.Get()
	if err != nil {
		return nil, false, err
	}

	validationErrs := []string{}

	for _, sig := range sl {
		verified, err := VerifyImageSignature(ctx, sig, h, co)
		bundleVerified = bundleVerified || verified
		if err != nil {
			validationErrs = append(validationErrs, err.Error())
			continue
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sig)
	}
	if len(checkedSignatures) == 0 {
		return nil, false, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, bundleVerified, nil
}

// VerifyImageSignature verifies a signature
func VerifyImageSignature(ctx context.Context, sig oci.Signature, h v1.Hash, co *CheckOpts) (bundleVerified bool, err error) {
	verifier := co.SigVerifier
	if verifier == nil {
		// If we don't have a public key to check against, we can try a root cert.
		cert, err := sig.Cert()
		if err != nil {
			return bundleVerified, err
		}
		if cert == nil {
			return bundleVerified, errors.New("no certificate found on signature")
		}
		// Create a certificate pool for intermediate CA certificates, excluding the root
		chain, err := sig.Chain()
		if err != nil {
			return bundleVerified, err
		}
		// If the chain annotation is not present or there is only a root
		if chain == nil || len(chain) <= 1 {
			co.IntermediateCerts = nil
		} else if co.IntermediateCerts == nil {
			// If the intermediate certs have not been loaded in by TUF
			pool := x509.NewCertPool()
			for _, cert := range chain[:len(chain)-1] {
				pool.AddCert(cert)
			}
			co.IntermediateCerts = pool
		}
		verifier, err = ValidateAndUnpackCert(cert, co)
		if err != nil {
			return bundleVerified, err
		}
	}

	if err := verifyOCISignature(ctx, verifier, sig); err != nil {
		return bundleVerified, err
	}

	// We can't check annotations without claims, both require unmarshalling the payload.
	if co.ClaimVerifier != nil {
		if err := co.ClaimVerifier(sig, h, co.Annotations); err != nil {
			return bundleVerified, err
		}
	}

	bundleVerified, err = VerifyBundle(ctx, sig)
	if err != nil && co.RekorClient == nil {
		return false, errors.Wrap(err, "unable to verify bundle")
	}

	if !bundleVerified && co.RekorClient != nil {
		if co.SigVerifier != nil {
			pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
			if err != nil {
				return bundleVerified, err
			}
			return bundleVerified, tlogValidatePublicKey(ctx, co.RekorClient, pub, sig)
		}

		return bundleVerified, tlogValidateCertificate(ctx, co.RekorClient, sig)
	}

	return bundleVerified, nil
}

func loadSignatureFromFile(sigRef string, signedImgRef name.Reference, co *CheckOpts) (oci.Signatures, error) {
	var b64sig string
	targetSig, err := blob.LoadFileOrURL(sigRef)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		targetSig = []byte(sigRef)
	}

	_, err = base64.StdEncoding.DecodeString(string(targetSig))

	if err == nil {
		b64sig = string(targetSig)
	} else {
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}

	digest, err := ociremote.ResolveDigest(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}

	payload, err := (&sigPayload.Cosign{Image: digest}).MarshalJSON()

	if err != nil {
		return nil, err
	}

	sig, err := static.NewSignature(payload, b64sig)
	if err != nil {
		return nil, err
	}
	return &fakeOCISignatures{
		signatures: []oci.Signature{sig},
	}, nil
}

// VerifyAttestations does all the main cosign checks in a loop, returning the verified attestations.
// If there were no valid attestations, we return an error.
func VerifyImageAttestations(ctx context.Context, signedImgRef name.Reference, co *CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, false, errors.New("one of verifier or root certs is required")
	}

	// TODO(mattmoor): We could implement recursive verification if we just wrapped
	// most of the logic below here in a call to mutate.Map

	se, h, err := getSignedEntity(signedImgRef, co.RegistryClientOpts)
	if err != nil {
		return nil, false, err
	}
	atts, err := se.Attestations()
	if err != nil {
		return nil, false, err
	}

	return verifyImageAttestations(ctx, atts, h, co)
}

// VerifyLocalImageAttestations verifies attestations from a saved, local image, without any network calls,
// returning the verified attestations.
// If there were no valid signatures, we return an error.
func VerifyLocalImageAttestations(ctx context.Context, path string, co *CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, false, errors.New("one of verifier or root certs is required")
	}

	se, err := layout.SignedImageIndex(path)
	if err != nil {
		return nil, false, err
	}

	var h v1.Hash
	// Verify either an image index or image.
	ii, err := se.SignedImageIndex(v1.Hash{})
	if err != nil {
		return nil, false, err
	}
	i, err := se.SignedImage(v1.Hash{})
	if err != nil {
		return nil, false, err
	}
	switch {
	case ii != nil:
		h, err = ii.Digest()
		if err != nil {
			return nil, false, err
		}
	case i != nil:
		h, err = i.Digest()
		if err != nil {
			return nil, false, err
		}
	default:
		return nil, false, errors.New("must verify either an image index or image")
	}

	atts, err := se.Attestations()
	if err != nil {
		return nil, false, err
	}
	return verifyImageAttestations(ctx, atts, h, co)
}

func verifyImageAttestations(ctx context.Context, atts oci.Signatures, h v1.Hash, co *CheckOpts) (checkedAttestations []oci.Signature, bundleVerified bool, err error) {
	sl, err := atts.Get()
	if err != nil {
		return nil, false, err
	}

	validationErrs := []string{}
	for _, att := range sl {
		if err := func(att oci.Signature) error {
			verifier := co.SigVerifier
			if verifier == nil {
				// If we don't have a public key to check against, we can try a root cert.
				cert, err := att.Cert()
				if err != nil {
					return err
				}
				if cert == nil {
					return errors.New("no certificate found on attestation")
				}
				// Create a certificate pool for intermediate CA certificates, excluding the root
				chain, err := att.Chain()
				if err != nil {
					return err
				}
				// If the chain annotation is not present or there is only a root
				if chain == nil || len(chain) <= 1 {
					co.IntermediateCerts = nil
				} else if co.IntermediateCerts == nil {
					// If the intermediate certs have not been loaded in by TUF
					pool := x509.NewCertPool()
					for _, cert := range chain[:len(chain)-1] {
						pool.AddCert(cert)
					}
					co.IntermediateCerts = pool
				}
				verifier, err = ValidateAndUnpackCert(cert, co)
				if err != nil {
					return err
				}
			}

			if err := verifyOCIAttestation(ctx, verifier, att); err != nil {
				return err
			}

			// We can't check annotations without claims, both require unmarshalling the payload.
			if co.ClaimVerifier != nil {
				if err := co.ClaimVerifier(att, h, co.Annotations); err != nil {
					return err
				}
			}

			verified, err := VerifyBundle(ctx, att)
			if err != nil && co.RekorClient == nil {
				return errors.Wrap(err, "unable to verify bundle")
			}
			bundleVerified = bundleVerified || verified

			if !verified && co.RekorClient != nil {
				if co.SigVerifier != nil {
					pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
					if err != nil {
						return err
					}
					return tlogValidatePublicKey(ctx, co.RekorClient, pub, att)
				}

				return tlogValidateCertificate(ctx, co.RekorClient, att)
			}
			return nil
		}(att); err != nil {
			validationErrs = append(validationErrs, err.Error())
			continue
		}

		// Phew, we made it.
		checkedAttestations = append(checkedAttestations, att)
	}
	if len(checkedAttestations) == 0 {
		return nil, false, fmt.Errorf("no matching attestations:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedAttestations, bundleVerified, nil
}

// CheckExpiry confirms the time provided is within the valid period of the cert
func CheckExpiry(cert *x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return fmt.Errorf("certificate expired before signatures were entered in log: %s is before %s",
			ft(cert.NotAfter), ft(it))
	}
	if cert.NotBefore.After(it) {
		return fmt.Errorf("certificate was issued after signatures were entered in log: %s is after %s",
			ft(cert.NotAfter), ft(it))
	}
	return nil
}

func VerifyBundle(ctx context.Context, sig oci.Signature) (bool, error) {
	bundle, err := sig.Bundle()
	if err != nil {
		return false, err
	} else if bundle == nil {
		return false, nil
	}

	if err := compareSigs(bundle.Payload.Body.(string), sig); err != nil {
		return false, err
	}

	publicKeys, err := GetRekorPubs(ctx)
	if err != nil {
		return false, errors.Wrap(err, "retrieving rekor public key")
	}

	pubKey, ok := publicKeys[bundle.Payload.LogID]
	if !ok {
		return false, errors.New("rekor log public key not found for payload")
	}
	err = VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, pubKey.PubKey)
	if err != nil {
		return false, err
	}
	if pubKey.Status != tuf.Active {
		fmt.Fprintf(os.Stderr, "**Info** Successfully verified Rekor entry using an expired verification key\n")
	}

	cert, err := sig.Cert()
	if err != nil {
		return false, err
	} else if cert == nil {
		return true, nil
	}

	// verify the cert against the integrated time
	if err := CheckExpiry(cert, time.Unix(bundle.Payload.IntegratedTime, 0)); err != nil {
		return false, errors.Wrap(err, "checking expiry on cert")
	}

	payload, err := sig.Payload()
	if err != nil {
		return false, errors.Wrap(err, "reading payload")
	}
	signature, err := sig.Base64Signature()
	if err != nil {
		return false, errors.Wrap(err, "reading base64signature")
	}

	alg, bundlehash, err := bundleHash(bundle.Payload.Body.(string), signature)
	h := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(h[:])

	if alg != "sha256" || bundlehash != payloadHash {
		return false, errors.Wrap(err, "matching bundle to payload")
	}
	return true, nil
}

// compare bundle signature to the signature we are verifying
func compareSigs(bundleBody string, sig oci.Signature) error {
	// TODO(nsmith5): modify function signature to make it more clear _why_
	// we've returned nil (there are several reasons possible here).
	actualSig, err := sig.Base64Signature()
	if err != nil {
		return errors.Wrap(err, "base64 signature")
	}
	if actualSig == "" {
		// NB: empty sig means this is an attestation
		return nil
	}
	bundleSignature, err := bundleSig(bundleBody)
	if err != nil {
		return errors.Wrap(err, "failed to extract signature from bundle")
	}
	if bundleSignature == "" {
		return nil
	}
	if bundleSignature != actualSig {
		return fmt.Errorf("signature in bundle does not match signature being verified")
	}
	return nil
}

func bundleHash(bundleBody, signature string) (string, string, error) {
	var toto models.Intoto
	var rekord models.Rekord
	var hrekord models.Hashedrekord
	var intotoObj models.IntotoV001Schema
	var rekordObj models.RekordV001Schema
	var hrekordObj models.HashedrekordV001Schema

	bodyDecoded, err := base64.StdEncoding.DecodeString(bundleBody)
	if err != nil {
		return "", "", err
	}

	// The fact that there's no signature (or empty rather), implies
	// that this is an Attestation that we're verifying.
	if len(signature) == 0 {
		err = json.Unmarshal(bodyDecoded, &toto)
		if err != nil {
			return "", "", err
		}

		specMarshal, err := json.Marshal(toto.Spec)
		if err != nil {
			return "", "", err
		}
		err = json.Unmarshal(specMarshal, &intotoObj)
		if err != nil {
			return "", "", err
		}

		return *intotoObj.Content.Hash.Algorithm, *intotoObj.Content.Hash.Value, nil
	}

	if err := json.Unmarshal(bodyDecoded, &rekord); err == nil {
		specMarshal, err := json.Marshal(rekord.Spec)
		if err != nil {
			return "", "", err
		}
		err = json.Unmarshal(specMarshal, &rekordObj)
		if err != nil {
			return "", "", err
		}
		return *rekordObj.Data.Hash.Algorithm, *rekordObj.Data.Hash.Value, nil
	}

	// Try hashedRekordObj
	err = json.Unmarshal(bodyDecoded, &hrekord)
	if err != nil {
		return "", "", err
	}
	specMarshal, err := json.Marshal(hrekord.Spec)
	if err != nil {
		return "", "", err
	}
	err = json.Unmarshal(specMarshal, &hrekordObj)
	if err != nil {
		return "", "", err
	}
	return *hrekordObj.Data.Hash.Algorithm, *hrekordObj.Data.Hash.Value, nil
}

// bundleSig extracts the signature from the rekor bundle body
func bundleSig(bundleBody string) (string, error) {
	var rekord models.Rekord
	var hrekord models.Hashedrekord
	var rekordObj models.RekordV001Schema
	var hrekordObj models.HashedrekordV001Schema

	bodyDecoded, err := base64.StdEncoding.DecodeString(bundleBody)
	if err != nil {
		return "", errors.Wrap(err, "decoding bundleBody")
	}

	// Try Rekord
	if err := json.Unmarshal(bodyDecoded, &rekord); err == nil {
		specMarshal, err := json.Marshal(rekord.Spec)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(specMarshal, &rekordObj); err != nil {
			return "", err
		}
		return rekordObj.Signature.Content.String(), nil
	}

	// Try hashedRekordObj
	if err := json.Unmarshal(bodyDecoded, &hrekord); err != nil {
		return "", err
	}
	specMarshal, err := json.Marshal(hrekord.Spec)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(specMarshal, &hrekordObj); err != nil {
		return "", err
	}
	return hrekordObj.Signature.Content.String(), nil
}

func VerifySET(bundlePayload cbundle.RekorPayload, signature []byte, pub *ecdsa.PublicKey) error {
	contents, err := json.Marshal(bundlePayload)
	if err != nil {
		return errors.Wrap(err, "marshaling")
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return errors.Wrap(err, "canonicalizing")
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		return errors.New("unable to verify")
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
		return nil, err
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
