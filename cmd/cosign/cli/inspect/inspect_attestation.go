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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/mitchellh/mapstructure"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/rekor/pkg/generated/client"
)

// InspectAttestationCommand provides attestation data associated to a supplied container image
// nolint
type InspectAttestationCommand struct {
	options.RegistryOptions
	Output           string
	RekorURL         string
	Attachment       string
	SignatureRef     string
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
		Offline:     c.Offline,
		IgnoreTlog:  c.IgnoreTlog,
		RekorClient: client,
	}

	for _, imageRef := range images {
		var attestations []oci.Signature

		if c.LocalImage {
			attestations, err = cosign.InspectLocalImageAttestations(ctx, imageRef, co)
			if err != nil {
				return err
			}
		} else {
			ref, err := name.ParseReference(imageRef, c.NameOptions...)
			if err != nil {
				return err
			}

			attestations, err = cosign.InspectImageAttestations(ctx, ref, co)
			if err != nil {
				return err
			}
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintInspectHeader(imageRef, "attestation")
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintInspectAttestation(ctx, imageRef, attestations, co, "text")
	}

	return nil
}

// PrintInspectAttestation outputs the details of the attestation to stdout for user inspection
func PrintInspectAttestation(
	ctx context.Context,
	imgRef string,
	attestations []oci.Signature,
	co *cosign.CheckOpts,
	output string,
) {
	switch output {
	case "text":
		for _, att := range attestations {
			payload, err := att.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}

			env := ssldsse.Envelope{}
			if err := json.Unmarshal(payload, &env); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"Error unmarshalling payload into DSSE Envelope format: %v",
					err,
				)
				return
			}

			pl, err := env.DecodeB64Payload()
			if err != nil {
				fmt.Fprintf(
					os.Stderr,
					"Error base64 decoding attestation predicate statement: %v",
					err,
				)
				return
			}

			var predicate in_toto.Statement
			json.Unmarshal(pl, &predicate)

			// TM: Stripping Out Predicate Data for ease of visibility. Not very happy with this code, feel like it could be way neater.
			var predicateData attestation.CosignPredicate
			err = mapstructure.Decode(predicate.Predicate, &predicateData)
			if err != nil {
				fmt.Fprintf(
					os.Stderr,
					"Error decoding predicate data map into struct: %v",
					err,
				)
			}

			fmt.Println("SubjectName:", predicate.Subject[0].Name)
			fmt.Printf("SubjectDigest: sha256:%s\n", predicate.Subject[0].Digest["sha256"])
			fmt.Println("Type:", predicate.Type)
			fmt.Println("PredicateType:", predicate.PredicateType)
			fmt.Println("Timestamp:", predicateData.Timestamp)
			fmt.Println("Predicate:", predicateData.Data)
		}

		// TM: Commented out for now as not certain whether this is a desired functionality
		// if co.IgnoreTlog == false {
		// 	err := PrintTlogInspection(ctx, imgRef, attestations, co)
		// 	if err != nil {
		// 		fmt.Println("Error generating transparency log output:", err.Error())
		// 	}
		// }

	default:
		for _, att := range attestations {
			p, err := att.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}
			fmt.Printf("%+v", string(p))
		}

		// TM: Commented out for now as not certain whether this is a desired functionality
		// if co.IgnoreTlog == false {
		// 	err := PrintTlogInspection(ctx, imgRef, attestations, co)
		// 	if err != nil {
		// 		fmt.Println("Error generating transparency log output:", err.Error())
		// 	}
		// }
	}
}
