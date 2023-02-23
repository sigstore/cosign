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
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/cue"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/cosign/rego"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/policy"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	CheckClaims                  bool
	KeyRef                       string
	CertRef                      string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertChain                    string
	IgnoreSCT                    bool
	SCTRef                       string
	Sk                           bool
	Slot                         string
	Output                       string
	RekorURL                     string
	PredicateType                string
	Policies                     []string
	LocalImage                   bool
	NameOptions                  []name.Option
	Offline                      bool
	TSACertChainPath             string
	IgnoreTlog                   bool
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	var identities []cosign.Identity
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts:           ociremoteOpts,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}
	if !c.IgnoreSCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	if c.TSACertChainPath != "" {
		_, err := os.Stat(c.TSACertChainPath)
		if err != nil {
			return fmt.Errorf("unable to open timestamp certificate chain file '%s: %w", c.TSACertChainPath, err)
		}
		// TODO: Add support for TUF certificates.
		pemBytes, err := os.ReadFile(filepath.Clean(c.TSACertChainPath))
		if err != nil {
			return fmt.Errorf("error reading certification chain path file: %w", err)
		}

		leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(pemBytes)
		if err != nil {
			return fmt.Errorf("error splitting certificates: %w", err)
		}
		if len(leaves) > 1 {
			return fmt.Errorf("certificate chain must contain at most one TSA certificate")
		}
		if len(leaves) == 1 {
			co.TSACertificate = leaves[0]
		}
		co.TSAIntermediateCertificates = intermediates
		co.TSARootCertificates = roots
	}
	if !c.IgnoreTlog {
		if c.RekorURL != "" {
			rekorClient, err := rekor.NewClient(c.RekorURL)
			if err != nil {
				return fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
		// This performs an online fetch of the Rekor public keys, but this is needed
		// for verifying tlog entries (both online and offline).
		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting Rekor public keys: %w", err)
		}
	}
	if keylessVerification(c.KeyRef, c.Sk) {
		// This performs an online fetch of the Fulcio roots. This is needed
		// for verifying keyless certificates (both online and offline).
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
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
			// If no certChain is passed, the Fulcio root certificate will be used
			co.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return fmt.Errorf("getting Fulcio roots: %w", err)
			}
			co.IntermediateCerts, err = fulcio.GetIntermediates()
			if err != nil {
				return fmt.Errorf("getting Fulcio intermediates: %w", err)
			}
			co.SigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
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
		if c.SCTRef != "" {
			sct, err := os.ReadFile(filepath.Clean(c.SCTRef))
			if err != nil {
				return fmt.Errorf("reading sct from file: %w", err)
			}
			co.SCT = sct
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
		// To aid in determining if there's a mismatch in what predicateType
		// we're looking for and what we checked, keep track of them here so
		// that we can help the user figure out if there's a typo, etc.
		checkedPredicateTypes := []string{}
		for _, vp := range verified {
			payload, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, vp)
			if err != nil {
				return fmt.Errorf("converting to consumable policy validation: %w", err)
			}
			checkedPredicateTypes = append(checkedPredicateTypes, gotPredicateType)
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
				fmt.Fprintf(os.Stderr, "will be validating against Rego policies: %v\n", regoPolicies)
				regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
				if len(regoValidationErrs) > 0 {
					validationErrors = append(validationErrors, regoValidationErrs...)
					continue
				}
			}

			checked = append(checked, vp)
		}

		if len(validationErrors) > 0 {
			fmt.Fprintf(os.Stderr, "There are %d number of errors occurred during the validation:\n", len(validationErrors))
			for _, v := range validationErrors {
				_, _ = fmt.Fprintf(os.Stderr, "- %v\n", v)
			}
			return fmt.Errorf("%d validation errors occurred", len(validationErrors))
		}

		if len(checked) == 0 {
			return fmt.Errorf("none of the attestations matched the predicate type: %s, found: %s", c.PredicateType, strings.Join(checkedPredicateTypes, ","))
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(imageRef, co, bundleVerified, fulcioVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, checked, "text")
	}

	return nil
}
