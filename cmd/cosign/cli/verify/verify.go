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
	"encoding/json"
	"flag"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
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

	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
	}

	// key and security key are mutually exclusive
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.PubKeyParseError{}
	}

	var identities []cosign.Identity
	if c.KeyRef == "" && !c.Sk {
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
	if c.AllowCertificateChain {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithBundleOptions(sgbundle.AllowCertificateChain()))
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
		AllowCertificateChain:        c.AllowCertificateChain,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)
	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	// User provides a key. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle or OCI annotation.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	fulcioVerified := (co.SigVerifier == nil)

	for _, img := range images {
		var verified []oci.Signature
		var bundleVerified bool
		var displayName string

		if c.LocalImage {
			verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, img, co)
			if err != nil {
				return err
			}
			displayName = img
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
			displayName = ref.Name()
		}

		verifiedOutput, err := transformOutput(verified, displayName)
		if err != nil {
			return err
		}
		if len(verifiedOutput) > 0 {
			PrintVerificationHeader(ctx, displayName, co, bundleVerified, fulcioVerified)
			PrintVerification(ctx, verifiedOutput, c.Output)
		} else {
			return fmt.Errorf("no matching signatures exist")
		}
	}

	return nil
}

func transformOutput(verified []oci.Signature, name string) (verifiedOutput []oci.Signature, err error) {
	// We might not understand bundles not produced by Cosign, so skip them
	for _, v := range verified {
		dssePayload, err := v.Payload()
		if err != nil {
			continue
		}
		var dsseEnvelope dsse.Envelope
		err = json.Unmarshal(dssePayload, &dsseEnvelope)
		if err != nil {
			continue
		}
		if dsseEnvelope.PayloadType != in_toto.PayloadType {
			continue
		}
		intotoStatement := &attestation.Statement{}
		err = intotoStatement.UnmarshalJSON(dsseEnvelope.Payload)
		if err != nil {
			continue
		}
		if len(intotoStatement.Subject) < 1 || len(intotoStatement.Subject[0].Digest) < 1 {
			continue
		}
		if intotoStatement.PredicateType != types.CosignSignPredicateType {
			continue
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
