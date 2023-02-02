//go:build exclude

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

package inspect

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/cue"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/cosign/rego"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/policy"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

// InspectAttestationCommand provides attestation data associated to a supplied container image
// nolint
type InspectAttestationCommand struct {
	options.RegistryOptions
	// options.CertVerifyOptions
	// CheckClaims                  bool
	// KeyRef                       string
	// CertRef                      string
	// CertGithubWorkflowTrigger    string
	// CertGithubWorkflowSha        string
	// CertGithubWorkflowName       string
	// CertGithubWorkflowRepository string
	// CertGithubWorkflowRef        string
	// CertChain                    string
	// CertOidcProvider             string
	// IgnoreSCT                    bool
	// SCTRef                       string
	// Sk                           bool
	// Slot                         string
	Output     string
	RekorURL   string
	Attachment string
	// Annotations                  sigs.AnnotationsMap
	SignatureRef string
	// HashAlgorithm                crypto.Hash
	LocalImage       bool
	NameOptions      []name.Option
	Offline          bool
	TSACertChainPath string
	IgnoreTlog       bool
}

// Exec runs the verification command
func (c *InspectAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	// We can't have both a key and a security key
	// if options.NOf(c.KeyRef, c.Sk) > 1 {
	// 	return &options.KeyParseError{}
	// }

	// var identities []cosign.Identity
	// if c.KeyRef == "" {
	// 	identities, err = c.Identities()
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	//

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	var client *client.Rekor
	if c.RekorURL != "" && c.IgnoreTlog != true {
		client, err = rekor.NewClient(c.RekorURL)
		if err != nil {
			return fmt.Errorf("creating Rekor client: %w", err)
		}
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts: ociremoteOpts,
		// CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		// CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		// CertGithubWorkflowName:       c.CertGithubWorkflowName,
		// CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		// CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		// IgnoreSCT:                    c.IgnoreSCT,
		// Identities:                   identities,
		Offline:    c.Offline,
		IgnoreTlog: c.IgnoreTlog,
		RekorClient: client
	}

	// if c.CheckClaims {
	// 	co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	// }
	// if !c.IgnoreSCT {
	// 	co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
	// 	if err != nil {
	// 		return fmt.Errorf("getting ctlog public keys: %w", err)
	// 	}
	// }

	// if c.TSACertChainPath != "" {
	// 	_, err := os.Stat(c.TSACertChainPath)
	// 	if err != nil {
	// 		return fmt.Errorf(
	// 			"unable to open timestamp certificate chain file '%s: %w",
	// 			c.TSACertChainPath,
	// 			err,
	// 		)
	// 	}
	// 	// TODO: Add support for TUF certificates.
	// 	pemBytes, err := os.ReadFile(filepath.Clean(c.TSACertChainPath))
	// 	if err != nil {
	// 		return fmt.Errorf("error reading certification chain path file: %w", err)
	// 	}
	//
	// 	leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(pemBytes)
	// 	if err != nil {
	// 		return fmt.Errorf("error splitting certificates: %w", err)
	// 	}
	// 	if len(leaves) > 1 {
	// 		return fmt.Errorf("certificate chain must contain at most one TSA certificate")
	// 	}
	// 	if len(leaves) == 1 {
	// 		co.TSACertificate = leaves[0]
	// 	}
	// 	co.TSAIntermediateCertificates = intermediates
	// 	co.TSARootCertificates = roots
	// }
	// 	// This performs an online fetch of the Rekor public keys, but this is needed
	// 	// for verifying tlog entries (both online and offline).
	// 	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	// 	if err != nil {
	// 		return fmt.Errorf("getting Rekor public keys: %w", err)
	// 	}
	// }
	// if keylessVerification(c.KeyRef, c.Sk) {
	// 	// This performs an online fetch of the Fulcio roots. This is needed
	// 	// for verifying keyless certificates (both online and offline).
	// 	co.RootCerts, err = fulcio.GetRoots()
	// 	if err != nil {
	// 		return fmt.Errorf("getting Fulcio roots: %w", err)
	// 	}
	// 	co.IntermediateCerts, err = fulcio.GetIntermediates()
	// 	if err != nil {
	// 		return fmt.Errorf("getting Fulcio intermediates: %w", err)
	// 	}
	// }
	// keyRef := c.KeyRef
	//

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	// fulcioVerified := (co.SigVerifier == nil)

	for _, imageRef := range images {
		var signatures []oci.Signature

		if c.LocalImage {
			verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, imageRef, co)
			if err != nil {
				return err
			}
		} else {
			ref, err := name.ParseReference(imageRef, c.NameOptions...)
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
			switch filepath.Ext(policy) {
			case ".rego":
				regoPolicies = append(regoPolicies, policy)
			case ".cue":
				cuePolicies = append(cuePolicies, policy)
			default:
				return errors.New("invalid policy format, expected .cue or .rego")
			}
		}

		var checked []oci.Signature
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
					continue
				}
			}

			if len(regoPolicies) > 0 {
				fmt.Fprintf(
					os.Stderr,
					"will be validating against Rego policies: %v\n",
					regoPolicies,
				)
				regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
				if len(regoValidationErrs) > 0 {
					validationErrors = append(validationErrors, regoValidationErrs...)
					continue
				}
			}

			checked = append(checked, vp)
		}

		if len(validationErrors) > 0 {
			fmt.Fprintf(
				os.Stderr,
				"There are %d number of errors occurred during the validation:\n",
				len(validationErrors),
			)
			for _, v := range validationErrors {
				_, _ = fmt.Fprintf(os.Stderr, "- %v\n", v)
			}
			return fmt.Errorf("%d validation errors occurred", len(validationErrors))
		}

		if len(checked) == 0 {
			return fmt.Errorf(
				"none of the attestations matched the predicate type: %s",
				c.PredicateType,
			)
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(imageRef, co, bundleVerified, fulcioVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, checked, "text")
	}

	return nil
}
