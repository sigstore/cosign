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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/cosign/rego"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/cue"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	CheckClaims   bool
	KeyRef        string
	Sk            bool
	Slot          string
	Output        string
	FulcioURL     string
	RekorURL      string
	PredicateType string
	Policies      []string
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	if !options.OneOf(c.KeyRef, c.Sk) && !options.EnableExperimental() {
		return &options.KeyParseError{}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}
	co := &cosign.CheckOpts{
		RegistryClientOpts: ociremoteOpts,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}
	if options.EnableExperimental() {
		co.RekorURL = c.RekorURL
		co.RootCerts = fulcio.GetRoots()
	}
	keyRef := c.KeyRef

	// Keys are optional!
	if keyRef != "" {
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	} else if c.Sk {
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		co.SigVerifier, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
	}

	for _, imageRef := range images {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}

		verified, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, co)
		if err != nil {
			return err
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

		var validationErrors []error
		for _, vp := range verified {
			var payloadData map[string]interface{}

			p, err := vp.Payload()
			if err != nil {
				return errors.Wrap(err, "could not get payload")
			}

			err = json.Unmarshal(p, &payloadData)
			if err != nil {
				return errors.Wrap(err, "unmarshal payload data")
			}

			predicateURI, ok := options.PredicateTypeMap[c.PredicateType]
			if !ok {
				return fmt.Errorf("invalid predicate type: %s", c.PredicateType)
			}

			// sanity checks
			if val, ok := payloadData["payloadType"]; ok {
				// we need to check only given type from the cli flag
				// so we are skipping other types
				if predicateURI != val {
					continue
				}
			} else {
				return fmt.Errorf("could not find 'payloadType' in payload data")
			}

			var decodedPayload []byte
			if val, ok := payloadData["payload"]; ok {
				decodedPayload, err = base64.StdEncoding.DecodeString(val.(string))
				if err != nil {
					return fmt.Errorf("could not decode 'payload': %w", err)
				}
			} else {
				return fmt.Errorf("could not find 'payload' in payload data")
			}

			var payload []byte
			switch c.PredicateType {
			case options.PredicateCustom:
				var cosignStatement in_toto.Statement
				if err := json.Unmarshal(decodedPayload, &cosignStatement); err != nil {
					return fmt.Errorf("unmarshal CosignStatement: %w", err)
				}
				payload, err = json.Marshal(cosignStatement)
				if err != nil {
					return fmt.Errorf("error when generating CosignStatement: %w", err)
				}
			case options.PredicateLink:
				var linkStatement in_toto.LinkStatement
				if err := json.Unmarshal(decodedPayload, &linkStatement); err != nil {
					return fmt.Errorf("unmarshal LinkStatement: %w", err)
				}
				payload, err = json.Marshal(linkStatement)
				if err != nil {
					return fmt.Errorf("error when generating LinkStatement: %w", err)
				}
			case options.PredicateSLSA:
				var slsaProvenanceStatement in_toto.ProvenanceStatement
				if err := json.Unmarshal(decodedPayload, &slsaProvenanceStatement); err != nil {
					return fmt.Errorf("unmarshal ProvenanceStatement: %w", err)
				}
				payload, err = json.Marshal(slsaProvenanceStatement)
				if err != nil {
					return fmt.Errorf("error when generating ProvenanceStatement: %w", err)
				}
			case options.PredicateSPDX:
				var spdxStatement in_toto.SPDXStatement
				if err := json.Unmarshal(decodedPayload, &spdxStatement); err != nil {
					return fmt.Errorf("unmarshal SPDXStatement: %w", err)
				}
				payload, err = json.Marshal(spdxStatement)
				if err != nil {
					return fmt.Errorf("error when generating SPDXStatement: %w", err)
				}
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
		PrintVerificationHeader(imageRef, co, bundleVerified)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, verified, "text")
	}

	return nil
}
