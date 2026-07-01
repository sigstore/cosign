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
	"encoding/json"
	"flag"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	options.CommonVerifyOptions
	CheckClaims                  bool
	KeyRef                       string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertOidcProvider             string
	IgnoreSCT                    bool
	Sk                           bool
	Slot                         string
	Output                       string
	Annotations                  sigs.AnnotationsMap
	HashAlgorithm                crypto.Hash
	LocalImage                   bool
	NameOptions                  []name.Option
	UseSignedTimestamps          bool
	IgnoreTlog                   bool
	MaxWorkers                   int
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
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
		Annotations:                  c.Annotations.Annotations,
		RegistryClientOpts:           ociremoteOpts,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		IgnoreTlog:                   c.IgnoreTlog,
		MaxWorkers:                   c.MaxWorkers,
		UseSignedTimestamps:          c.UseSignedTimestamps,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)

	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	// User provides a key. Otherwise, verification requires a Fulcio certificate provided in an
	// attached bundle or OCI annotation.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.HashAlgorithm, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We’re going to find an x509 certificate on the signature and verify against
	//    Fulcio root trust (or user supplied root trust)
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, img := range images {
		var verified []oci.Signature
		var bundleVerified bool

		if c.LocalImage {
			verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, img, co)
			if err != nil {
				return err
			}
			PrintVerificationHeader(ctx, img, co, bundleVerified, fulcioVerified)
			PrintVerification(ctx, verified, c.Output)
		} else {
			ref, err := name.ParseReference(img, c.NameOptions...)
			if err != nil {
				return fmt.Errorf("parsing reference: %w", err)
			}

			// OCI bundle always contains attestation
			verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co, c.NameOptions...)
			if err != nil {
				return err
			}

			verifiedOutput, err := transformOutput(verified, ref.Name())
			if err == nil {
				verified = verifiedOutput
			}

			PrintVerificationHeader(ctx, ref.Name(), co, bundleVerified, fulcioVerified)
			PrintVerification(ctx, verified, c.Output)
		}
	}

	return nil
}

func transformOutput(verified []oci.Signature, name string) (verifiedOutput []oci.Signature, err error) {
	for _, v := range verified {
		dssePayload, err := v.Payload()
		if err != nil {
			return nil, err
		}
		var dsseEnvelope dsse.Envelope
		err = json.Unmarshal(dssePayload, &dsseEnvelope)
		if err != nil {
			return nil, err
		}
		if dsseEnvelope.PayloadType != in_toto.PayloadType {
			return nil, fmt.Errorf("unable to understand payload type %s", dsseEnvelope.PayloadType)
		}
		intotoStatement := &attestation.Statement{}
		err = intotoStatement.UnmarshalJSON(dsseEnvelope.Payload)
		if err != nil {
			return nil, err
		}
		if len(intotoStatement.Subject) < 1 || len(intotoStatement.Subject[0].Digest) < 1 {
			return nil, fmt.Errorf("no intoto subject or digest found")
		}

		var digest string
		for k, v := range intotoStatement.Subject[0].Digest {
			digest = k + ":" + v
		}
		annotations := intotoStatement.Subject[0].Annotations.AsMap()

		sci := payload.SimpleContainerImage{
			Critical: payload.Critical{
				Identity: payload.Identity{
					DockerReference: name,
				},
				Image: payload.Image{
					DockerManifestDigest: digest,
				},
				Type: intotoStatement.PredicateType,
			},
			Optional: annotations,
		}
		p, err := json.Marshal(sci)
		if err != nil {
			return nil, err
		}
		att, err := static.NewAttestation(p)
		if err != nil {
			return nil, err
		}
		verifiedOutput = append(verifiedOutput, att)
	}

	return verifiedOutput, nil
}
