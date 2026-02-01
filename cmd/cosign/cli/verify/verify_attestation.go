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
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/cue"
	"github.com/sigstore/cosign/v3/pkg/cosign/rego"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/policy"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	options.CommonVerifyOptions
	CheckClaims                  bool
	KeyRef                       string
	CertRef                      string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CAIntermediates              string
	CARoots                      string
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
	MaxWorkers                   int
	UseSignedTimestamps          bool
	HashAlgorithm                crypto.Hash
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
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
	if c.AllowHTTPRegistry || c.AllowInsecure {
		c.NameOptions = append(c.NameOptions, name.Insecure)
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
		MaxWorkers:                   c.MaxWorkers,
		UseSignedTimestamps:          c.TSACertChainPath != "" || c.UseSignedTimestamps,
		NewBundleFormat:              c.NewBundleFormat,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.CertRef, c.Sk, co)

	// Auto-detect bundle format for local images
	if c.LocalImage {
		hasBundles, err := cosign.HasLocalAttestationBundles(images[0])
		if err != nil {
			return fmt.Errorf("checking local image format: %w", err)
		}
		co.NewBundleFormat = hasBundles
	} else {
		ref, err := name.ParseReference(images[0], c.NameOptions...)
		if err == nil && c.NewBundleFormat {
			newBundles, _, err := cosign.GetBundles(ctx, ref, co.RegistryClientOpts, c.NameOptions...)
			if len(newBundles) == 0 || err != nil {
				co.NewBundleFormat = false
			}
		}
	}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	err = SetTrustedMaterial(ctx, c.TrustedRootPath, c.CertChain, c.CARoots, c.CAIntermediates, c.TSACertChainPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	if err = CheckSigstoreBundleUnsupportedOptions(*c, vOfflineKey, co); err != nil {
		return err
	}

	err = SetLegacyClientsAndKeys(ctx, c.IgnoreTlog, shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk), keylessVerification(c.KeyRef, c.Sk), c.RekorURL, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, co)
	if err != nil {
		return fmt.Errorf("setting up clients and keys: %w", err)
	}

	// User provides a key or certificate. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle or OCI annotation. LoadVerifierFromKeyOrCert must be called
	// after initializing trust material in order to verify certificate chain.
	var closeSV func()
	co.SigVerifier, _, closeSV, err = LoadVerifierFromKeyOrCert(ctx, c.KeyRef, c.Slot, c.CertRef, c.CertChain, c.HashAlgorithm, c.Sk, false, co)
	if err != nil {
		return fmt.Errorf("loading verifierfrom key opts: %w", err)
	}
	defer closeSV()

	if c.CertRef != "" && c.SCTRef != "" {
		sct, err := os.ReadFile(filepath.Clean(c.SCTRef))
		if err != nil {
			return fmt.Errorf("reading sct from file: %w", err)
		}
		co.SCT = sct
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

			verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co, c.NameOptions...)
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
				ui.Infof(ctx, "will be validating against CUE policies: %v", cuePolicies)
				cueValidationErr := cue.ValidateJSON(payload, cuePolicies)
				if cueValidationErr != nil {
					validationErrors = append(validationErrors, cueValidationErr)
					continue
				}
			}

			if len(regoPolicies) > 0 {
				ui.Infof(ctx, "will be validating against Rego policies: %v", regoPolicies)
				regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
				if len(regoValidationErrs) > 0 {
					validationErrors = append(validationErrors, regoValidationErrs...)
					continue
				}
			}

			checked = append(checked, vp)
		}

		if len(validationErrors) > 0 {
			ui.Infof(ctx, "There are %d number of errors occurred during the validation:\n", len(validationErrors))
			for _, v := range validationErrors {
				ui.Infof(ctx, "- %v", v)
			}
			return fmt.Errorf("%d validation errors occurred", len(validationErrors))
		}

		if len(checked) == 0 {
			return fmt.Errorf("none of the attestations matched the predicate type: %s, found: %s", c.PredicateType, strings.Join(checkedPredicateTypes, ","))
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(ctx, imageRef, co, bundleVerified, fulcioVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(ctx, checked, "text")
	}

	return nil
}
