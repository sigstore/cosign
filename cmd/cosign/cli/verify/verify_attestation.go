//
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

package verify

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	ociremote "github.com/sigstore/cosign/pkg/oci/remote"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/cosign/rego"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/cue"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/policy"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	CheckClaims    bool
	KeyRef         string
	CertRef        string
	CertEmail      string
	CertOidcIssuer string
	CertChain      string
	EnforceSCT     bool
	Sk             bool
	Slot           string
	Output         string
	RekorURL       string
	PredicateType  string
	Policies       []string
	LocalImage     bool
}

const (
	openPolicyAgentConfigMediaType      = "application/vnd.cncf.openpolicyagent.config.v1+json"
	openPolicyAgentPolicyLayerMediaType = "application/vnd.cncf.openpolicyagent.policy.layer.v1+rego"
)

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	if !options.OneOf(c.KeyRef, c.Sk, c.CertRef) && !options.EnableExperimental() {
		return &options.PubKeyParseError{}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	co := &cosign.CheckOpts{
		RegistryClientOpts: ociremoteOpts,
		CertEmail:          c.CertEmail,
		CertOidcIssuer:     c.CertOidcIssuer,
		EnforceSCT:         c.EnforceSCT,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}
	if options.EnableExperimental() {
		if c.RekorURL != "" {
			rekorClient, err := rekor.NewClient(c.RekorURL)
			if err != nil {
				return fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
		co.RootCerts = fulcio.GetRoots()
		co.IntermediateCerts = fulcio.GetIntermediates()
	}
	keyRef := c.KeyRef

	// Keys are optional!
	switch {
	case keyRef != "":
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		co.SigVerifier, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("initializing piv token verifier: %w", err)
		}
	case c.CertRef != "":
		cert, err := loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return fmt.Errorf("loading certificate from reference: %w", err)
		}
		if c.CertChain == "" {
			err = cosign.CheckCertificatePolicy(cert, co)
			if err != nil {
				return err
			}
			co.SigVerifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
			if err != nil {
				return fmt.Errorf("creating certificate verifier: %w", err)
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(c.CertChain)
			if err != nil {
				return err
			}
			co.SigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return fmt.Errorf("creating certificate verifier: %w", err)
			}
		}
	}

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, imageRef := range images {
		var verified []oci.Signature
		var bundleVerified bool

		if c.LocalImage {
			verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, imageRef, co)
			if err != nil {
				return err
			}
		} else {
			ref, err := name.ParseReference(imageRef)
			if err != nil {
				return err
			}

			verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co)
			if err != nil {
				return err
			}
		}

		var cuePolicies, regoPolicies []string

		for _, policy := range c.Policies {
			ext := filepath.Ext(policy)
			if ext != "" {
				if _, err := os.Stat(policy); errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("%s is not exists", policy)
				}
				switch ext {
				case ".rego":
					regoPolicies = append(regoPolicies, policy)
				case ".cue":
					cuePolicies = append(cuePolicies, policy)
				default:

					return fmt.Errorf("invalid policy format %s, expected formats: [.cue,.rego]", ext)
				}
			} else {
				policyImageRef, err := name.ParseReference(policy)
				if err == nil {
					img, err := ociremote.SignedImage(policyImageRef, co.RegistryClientOpts...)
					if err != nil {
						return fmt.Errorf("reading image %q: %w", policyImageRef, err)
					}

					s, err := img.Signatures()
					if err != nil {
						return fmt.Errorf("reading image %q: %w", policyImageRef, err)
					}

					policyImageSigs, err := s.Get()
					if err != nil {
						return fmt.Errorf("reading image %q: %w", policyImageRef, err)
					}

					if len(policyImageSigs) == 0 {
						return fmt.Errorf("no signature found for policy image %q, you should sign it", policyImageRef)
					}

					m, err := img.Manifest()
					if err != nil {
						return fmt.Errorf("reading image %q: %w", policyImageRef, err)
					}

					if !strings.EqualFold(string(m.Config.MediaType), openPolicyAgentConfigMediaType) {
						return fmt.Errorf("we are only supporting images suitable with OPA image spec, "+
							"given image %q is not compatible with that, "+
							"please refer to the page for more information: https://www.conftest.dev/sharing/", policyImageRef)
					}

					layers, err := img.Layers()
					if err != nil {
						return fmt.Errorf("reading image %q: %w", policyImageRef, err)
					}

					for _, layer := range layers {
						layerMediaType, err := layer.MediaType()
						if err != nil {
							return fmt.Errorf("reading image %q: %w", policyImageRef, err)
						}
						if strings.EqualFold(string(layerMediaType), openPolicyAgentPolicyLayerMediaType) {
							rc, err := layer.Uncompressed()
							if err != nil {
								return fmt.Errorf("reading image %q: %w", policyImageRef, err)
							}

							tmp, err := ioutil.TempFile("", "crane-append")
							if err != nil {
								return fmt.Errorf("reading image %q: %w", policyImageRef, err)
							}
							defer os.Remove(tmp.Name())

							if _, err := io.Copy(tmp, rc); err != nil {
								return fmt.Errorf("reading image %q: %w", policyImageRef, err)
							}
							regoPolicies = append(regoPolicies, tmp.Name())
						}
					}
				}
			}
		}

		var validationErrors []error
		for _, vp := range verified {
			payload, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, vp)
			if err != nil {
				return fmt.Errorf("converting to consumable policy validation: %w", err)
			}
			if len(payload) == 0 {
				// This is not the predicate type we're looking for.
				continue
			}

			if len(cuePolicies) > 0 {
				fmt.Fprintf(os.Stderr, "will be validating against CUE policies: %v\n", cuePolicies)
				cueValidationErr := cue.ValidateJSON(payload, cuePolicies)
				if cueValidationErr != nil {
					validationErrors = append(validationErrors, cueValidationErr)
				}
			}

			if len(regoPolicies) > 0 {
				fmt.Fprintf(os.Stderr, "will be validating against Rego policies: %v\n", regoPolicies)
				regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
				if len(regoValidationErrs) > 0 {
					validationErrors = append(validationErrors, regoValidationErrs...)
				}
			}
		}

		if len(validationErrors) > 0 {
			fmt.Fprintf(os.Stderr, "There are %d number of errors occurred during the validation:\n", len(validationErrors))
			for _, v := range validationErrors {
				_, _ = fmt.Fprintf(os.Stderr, "- %v\n", v)
			}
			return fmt.Errorf("%d validation errors occurred", len(validationErrors))
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(imageRef, co, bundleVerified, fulcioVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, verified, "text")
	}

	return nil
}
