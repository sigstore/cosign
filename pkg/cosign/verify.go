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
	"fmt"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// CheckOpts are the options for checking signatures.
type CheckOpts struct {
	// RegistryClientOpts are the options for interacting with the container registry.
	RegistryClientOpts []ociremote.Option

	// Annotations optionally specifies image signature annotations to verify.
	Annotations map[string]interface{}
	// ClaimVerifier, if provided, verifies claims present in the oci.Signature.
	ClaimVerifier func(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error

	// RekorURL is the URL for the rekor server to use to verify signatures and public keys.
	RekorURL string

	// SigVerifier is used to verify signatures.
	SigVerifier signature.Verifier
	// PKOpts are the options provided to `SigVerifier.PublicKey()`.
	PKOpts []signature.PublicKeyOption

	// RootCerts are the root CA certs used to verify a signature's chained certificate.
	RootCerts *x509.CertPool
	// CertEmail is the email expected for a certificate to be valid. The empty string means any certificate can be valid.
	CertEmail string
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

func verifyOCIAttestation(_ context.Context, verifier signature.Verifier, att oci.Signature) error {
	// TODO(dekkagaijin): plumb through context
	payload, err := att.Payload()
	if err != nil {
		return err
	}

	env := ssldsse.Envelope{}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil
	}

	dssev := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: verifier})
	return dssev.Verify(&env)
}

func validateAndUnpackCert(cert *x509.Certificate, co *CheckOpts) (signature.Verifier, error) {
	verifier, err := signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
	if err != nil {
		return nil, errors.Wrap(err, "invalid certificate found on signature")
	}

	// Now verify the cert, then the signature.
	if err := TrustedCert(cert, co.RootCerts); err != nil {
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
	return verifier, nil
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
	_, _, err = FindTlogEntry(ctx, rekorClient, b64sig, payload, pemBytes)
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
	uuid, _, err := FindTlogEntry(ctx, rekorClient, b64sig, payload, pemBytes)
	if err != nil {
		return err
	}
	// if we have a cert, we should check expiry
	// The IntegratedTime verified in VerifyTlog
	e, err := GetTlogEntry(ctx, rekorClient, uuid)
	if err != nil {
		return err
	}
	return checkExpiry(cert, time.Unix(*e.IntegratedTime, 0))
}

// VerifySignatures does all the main cosign checks in a loop, returning the verified signatures.
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
	sigs, err := se.Signatures()
	if err != nil {
		return nil, false, err
	}
	sl, err := sigs.Get()
	if err != nil {
		return nil, false, err
	}

	validationErrs := []string{}

	var rekorClient *client.Rekor
	if co.RekorURL != "" {
		rekorClient, err = rekor.GetRekorClient(co.RekorURL)
		if err != nil {
			return nil, false, err
		}
	}

	for _, sig := range sl {
		if err := func(sig oci.Signature) error {
			verifier := co.SigVerifier
			if verifier == nil {
				// If we don't have a public key to check against, we can try a root cert.
				cert, err := sig.Cert()
				if err != nil {
					return err
				}
				if cert == nil {
					return errors.New("no certificate found on signature")
				}
				verifier, err = validateAndUnpackCert(cert, co)
				if err != nil {
					return err
				}
			}

			if err := verifyOCISignature(ctx, verifier, sig); err != nil {
				return err
			}

			// We can't check annotations without claims, both require unmarshalling the payload.
			if co.ClaimVerifier != nil {
				if err := co.ClaimVerifier(sig, h, co.Annotations); err != nil {
					return err
				}
			}

			verified, err := VerifyBundle(ctx, sig)
			if err != nil && co.RekorURL == "" {
				return errors.Wrap(err, "unable to verify bundle")
			}
			bundleVerified = bundleVerified || verified

			if !verified && co.RekorURL != "" {
				if co.SigVerifier != nil {
					pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
					if err != nil {
						return err
					}
					return tlogValidatePublicKey(ctx, rekorClient, pub, sig)
				}

				return tlogValidateCertificate(ctx, rekorClient, sig)
			}
			return nil
		}(sig); err != nil {
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
	sl, err := atts.Get()
	if err != nil {
		return nil, false, err
	}

	validationErrs := []string{}

	var rekorClient *client.Rekor
	if co.RekorURL != "" {
		rekorClient, err = rekor.GetRekorClient(co.RekorURL)
		if err != nil {
			return nil, false, err
		}
	}
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
				verifier, err = validateAndUnpackCert(cert, co)
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
			if err != nil && co.RekorURL == "" {
				return errors.Wrap(err, "unable to verify bundle")
			}
			bundleVerified = bundleVerified || verified

			if !verified && co.RekorURL != "" {
				if co.SigVerifier != nil {
					pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
					if err != nil {
						return err
					}
					return tlogValidatePublicKey(ctx, rekorClient, pub, att)
				}

				return tlogValidateCertificate(ctx, rekorClient, att)
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

func checkExpiry(cert *x509.Certificate, it time.Time) error {
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

	rekorPubKey, err := PemToECDSAKey([]byte(GetRekorPub(ctx)))
	if err != nil {
		return false, errors.Wrap(err, "pem to ecdsa")
	}

	if err := VerifySET(bundle.Payload, bundle.SignedEntryTimestamp, rekorPubKey); err != nil {
		return false, err
	}

	cert, err := sig.Cert()
	if err != nil {
		return false, err
	} else if cert == nil {
		return true, nil
	}

	// verify the cert against the integrated time
	if err := checkExpiry(cert, time.Unix(bundle.Payload.IntegratedTime, 0)); err != nil {
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

func bundleHash(bundleBody, signature string) (string, string, error) {
	var toto models.Intoto
	var rekord models.Rekord
	var intotoObj models.IntotoV001Schema
	var rekordObj models.RekordV001Schema

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

	err = json.Unmarshal(bodyDecoded, &rekord)
	if err != nil {
		return "", "", err
	}

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

func VerifySET(bundlePayload oci.BundlePayload, signature []byte, pub *ecdsa.PublicKey) error {
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

func TrustedCert(cert *x509.Certificate, roots *x509.CertPool) error {
	if _, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime: cert.NotBefore,
		Roots:       roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageDigitalSignature),
			x509.ExtKeyUsageCodeSigning,
		},
	}); err != nil {
		return err
	}
	return nil
}

func correctAnnotations(wanted, have map[string]interface{}) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
