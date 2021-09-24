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
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
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

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func Verify(ctx context.Context, signedImgRef name.Reference, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	// Enforce this up front.
	if co.RootCerts == nil && co.SigVerifier == nil {
		return nil, false, errors.New("one of verifier or root certs is required")
	}

	validationErrs := []string{}
	var rekorClient *client.Rekor
	if co.RekorURL != "" {
		rekorClient, err = rekor.GetRekorClient(co.RekorURL)
		if err != nil {
			return nil, false, err
		}
	}

	se, err := ociremote.SignedEntity(signedImgRef, co.RegistryClientOpts...)
	if err != nil {
		return nil, false, err
	}
	// Both of the SignedEntity types implement Digest()
	h, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
	if err != nil {
		return nil, false, err
	}

	// TODO(mattmoor): We could implement recursive verification if we just wrapped
	// most of the logic below here in a call to mutate.Map

	sigs, err := se.Signatures()
	if err != nil {
		return nil, false, err
	}
	sl, err := sigs.Get()
	if err != nil {
		return nil, false, err
	}
	for _, sig := range sl {
		if err := func(sig oci.Signature) error {
			b64sig, err := sig.Base64Signature()
			if err != nil {
				return err
			}
			payload, err := sig.Payload()
			if err != nil {
				return err
			}
			cert, err := sig.Cert()
			if err != nil {
				return err
			}

			switch {
			// We have a public key to check against.
			case co.SigVerifier != nil:
				signature, err := base64.StdEncoding.DecodeString(b64sig)
				if err != nil {
					return err
				}
				if err := co.SigVerifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
					return err
				}
			// If we don't have a public key to check against, we can try a root cert.
			case co.RootCerts != nil:
				// There might be signatures with a public key instead of a cert, though
				if cert == nil {
					return errors.New("no certificate found on signature")
				}
				pub, err := signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
				if err != nil {
					return errors.Wrap(err, "invalid certificate found on signature")
				}
				// Now verify the cert, then the signature.
				if err := TrustedCert(cert, co.RootCerts); err != nil {
					return err
				}

				signature, err := base64.StdEncoding.DecodeString(b64sig)
				if err != nil {
					return err
				}
				if err := pub.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
					return err
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
						return errors.New("expected email not found in certificate")
					}
				}
			}

			// We can't check annotations without claims, both require unmarshalling the payload.
			if co.ClaimVerifier != nil {
				if err := co.ClaimVerifier(sig, h, co.Annotations); err != nil {
					return err
				}
			}

			verified, err := VerifyBundle(sig)
			if err != nil && co.RekorURL == "" {
				return errors.Wrap(err, "unable to verify bundle")
			}
			bundleVerified = bundleVerified || verified

			if !verified && co.RekorURL != "" {
				// Get the right public key to use (key or cert)
				var pemBytes []byte
				if co.SigVerifier != nil {
					var pub crypto.PublicKey
					pub, err = co.SigVerifier.PublicKey(co.PKOpts...)
					if err != nil {
						return err
					}
					pemBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
				} else {
					pemBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
				}
				if err != nil {
					return err
				}

				// Find the uuid then the entry.
				uuid, _, err := FindTlogEntry(rekorClient, b64sig, payload, pemBytes)
				if err != nil {
					return err
				}

				// if we have a cert, we should check expiry
				// The IntegratedTime verified in VerifyTlog
				if cert != nil {
					e, err := getTlogEntry(rekorClient, uuid)
					if err != nil {
						return err
					}

					// Expiry check is only enabled with Tlog support
					if err := checkExpiry(cert, time.Unix(*e.IntegratedTime, 0)); err != nil {
						return err
					}
				}
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

func VerifyBundle(sig oci.Signature) (bool, error) {
	bundle, err := sig.Bundle()
	if err != nil {
		return false, err
	} else if bundle == nil {
		return false, nil
	}

	rekorPubKey, err := PemToECDSAKey([]byte(GetRekorPub()))
	if err != nil {
		return false, errors.Wrap(err, "pem to ecdsa")
	}

	if err := VerifySET(bundle.Payload, []byte(bundle.SignedEntryTimestamp), rekorPubKey); err != nil {
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
