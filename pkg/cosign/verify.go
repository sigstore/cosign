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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/internal/oci"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// CheckOpts are the options for checking signatures.
type CheckOpts struct {
	// SigTagSuffixOverride overrides the suffix of the derived signature image tag. Default: ".sig"
	SigTagSuffixOverride string
	// RegistryClientOpts are the options for interacting with the container registry.
	RegistryClientOpts []remote.Option

	// Annotations optionally specifies image signature annotations to verify.
	Annotations map[string]interface{}
	// ClaimVerifier, if provided, verifies claims present in the SignedPayload.
	ClaimVerifier  func(sigPayload SignedPayload, imageDigest v1.Hash, annotations map[string]interface{}) error
	BundleVerified bool //TODO: remove in favor of SignedPayload.BundleVerified

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

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func Verify(ctx context.Context, signedImgRef name.Reference, co *CheckOpts) ([]SignedPayload, error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, errors.New("one of verifier or root certs is required")
	}

	// Always lookup digest from remote to prevent impersonation and zombie verification
	signedImgDesc, err := remote.Get(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	h := signedImgDesc.Descriptor.Digest

	opts := []ociremote.Option{
		ociremote.WithRemoteOptions(co.RegistryClientOpts...),
	}

	// These are all the signatures attached to our image that we know how to parse.
	if co.SigTagSuffixOverride != "" {
		opts = append(opts, ociremote.WithSignatureSuffix(co.SigTagSuffixOverride))
	}

	// TODO(mattmoor): If we change this code to interact with the SignedImage directly,
	// then we could shed the `remote.Get` above.
	allSignatures, err := FetchSignaturesForReference(ctx, signedImgRef, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "fetching signatures")
	}

	validationErrs := []string{}
	checkedSignatures := []SignedPayload{}
	var rekorClient *client.Rekor
	for _, sp := range allSignatures {
		switch {
		// We have a public key to check against.
		case co.SigVerifier != nil:
			signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if err := co.SigVerifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(sp.Payload), options.WithContext(ctx)); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		// If we don't have a public key to check against, we can try a root cert.
		case co.RootCerts != nil:
			// There might be signatures with a public key instead of a cert, though
			if sp.Cert == nil {
				validationErrs = append(validationErrs, "no certificate found on signature")
				continue
			}
			pub, err := signature.LoadECDSAVerifier(sp.Cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
			if err != nil {
				validationErrs = append(validationErrs, "invalid certificate found on signature")
				continue
			}
			// Now verify the cert, then the signature.
			if err := TrustedCert(sp.Cert, co.RootCerts); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if err := pub.VerifySignature(bytes.NewReader(signature), bytes.NewReader(sp.Payload), options.WithContext(ctx)); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if co.CertEmail != "" {
				emailVerified := false
				for _, em := range sp.Cert.EmailAddresses {
					if co.CertEmail == em {
						emailVerified = true
						break
					}
				}
				if !emailVerified {
					validationErrs = append(validationErrs, "expected email not found in certificate")
					continue
				}
			}
		}

		// We can't check annotations without claims, both require unmarshalling the payload.
		if co.ClaimVerifier != nil {
			if err := co.ClaimVerifier(sp, h, co.Annotations); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		}

		verified, err := VerifyBundle(sp)
		if err != nil && co.RekorURL == "" {
			validationErrs = append(validationErrs, "unable to verify bundle: "+err.Error())
			continue
		}
		co.BundleVerified = verified

		if !verified && co.RekorURL != "" {
			if rekorClient == nil {
				rekorClient, err = rekor.GetRekorClient(co.RekorURL)
				if err != nil {
					validationErrs = append(validationErrs, "creating rekor client: "+err.Error())
					continue
				}
			}
			// Get the right public key to use (key or cert)
			var pemBytes []byte
			if co.SigVerifier != nil {
				var pub crypto.PublicKey
				pub, err = co.SigVerifier.PublicKey(co.PKOpts...)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
				pemBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
			} else {
				pemBytes, err = cryptoutils.MarshalCertificateToPEM(sp.Cert)
			}
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			// Find the uuid then the entry.
			uuid, _, err := FindTlogEntry(rekorClient, sp.Base64Signature, sp.Payload, pemBytes)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			// if we have a cert, we should check expiry
			// The IntegratedTime verified in VerifyTlog
			if sp.Cert != nil {
				e, err := getTlogEntry(rekorClient, uuid)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}

				// Expiry check is only enabled with Tlog support
				if err := checkExpiry(sp.Cert, time.Unix(*e.IntegratedTime, 0)); err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			}
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sp)
	}
	if len(checkedSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, nil
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

func VerifyBundle(sp SignedPayload) (bool, error) {
	if sp.Bundle == nil {
		return false, nil
	}
	rekorPubKey, err := PemToECDSAKey([]byte(GetRekorPub()))
	if err != nil {
		return false, errors.Wrap(err, "pem to ecdsa")
	}

	if err := VerifySET(sp.Bundle.Payload, []byte(sp.Bundle.SignedEntryTimestamp), rekorPubKey); err != nil {
		return false, err
	}

	if sp.Cert == nil {
		return true, nil
	}

	// verify the cert against the integrated time
	if err := checkExpiry(sp.Cert, time.Unix(sp.Bundle.Payload.IntegratedTime, 0)); err != nil {
		return false, errors.Wrap(err, "checking expiry on cert")
	}
	return true, nil
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
