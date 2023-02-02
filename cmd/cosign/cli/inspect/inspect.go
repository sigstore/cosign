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

package inspect

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// InspectCommand provides signature data associated to a supplied container image
// nolint
type InspectCommand struct {
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

// Exec runs the inspect command
func (c *InspectCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom", "":
		break
	default:
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
			return fmt.Errorf("failed to initiate Rekor client: %s", err.Error())
		}
	}

	co := &cosign.CheckOpts{
		// Annotations:                  c.Annotations.Annotations,
		RegistryClientOpts: ociremoteOpts,
		// CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		// CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		// CertGithubWorkflowN`1ame:       c.CertGithubWorkflowName,
		// CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		// CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		// IgnoreSCT:                    c.IgnoreSCT,
		SignatureRef: c.SignatureRef,
		// Identities:                   identities,
		Offline:     c.Offline,
		IgnoreTlog:  c.IgnoreTlog,
		RekorClient: client,
	}

	for _, img := range images {
		if c.LocalImage {
			sigs, err := cosign.InspectLocalImageSignatures(ctx, img, co)
			if err != nil {
				return err
			}
			PrintInspectionHeader(img, "signature")
			PrintInspection(ctx, img, sigs, co, c.Output)
		} else {
			ref, err := name.ParseReference(img, c.NameOptions...)
			if err != nil {
				return fmt.Errorf("parsing reference: %w", err)
			}
			ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
			if err != nil {
				return fmt.Errorf("resolving attachment type %s for image %s: %w", c.Attachment, img, err)
			}

			sigs, err := cosign.InspectImageSignatures(ctx, ref, co)
			if err != nil {
				return err
			}

			PrintInspectionHeader(ref.Name(), "signature")
			PrintInspection(ctx, ref.Name(), sigs, co, c.Output)
		}
	}

	return nil
}

func PrintTlogInspection(
	ctx context.Context,
	imgRef string,
	signatures []oci.Signature,
	co *cosign.CheckOpts,
) error {
	for _, sig := range signatures {
		// no rekor client provided for an online lookup
		if co.RekorClient == nil {
			err := fmt.Errorf("rekor client not initiated.")
			return err
		}

		pemBytes, err := cosign.KeyBytes(sig, co)
		if err != nil {
			return err
		}

		tlogEntries, err := cosign.InspectTlogEntries(ctx, co.RekorClient, sig, pemBytes)
		fmt.Printf("TlogEntries: %v", tlogEntries)
	}
	return nil
}

// InspectHeader provides a generic output (to `stderr`) header taking the image reference and artifact kind (e.g., signature, attestation, sbom) as input
func PrintInspectionHeader(imgRef string, kind string) {
	fmt.Fprintln(
		os.Stderr,
		"**Warning** This command does not verify any signatures for the image or associated artifacts (e.g., attestations, signatures etc.\nPlease use `cosign verify` to perform these actions.",
	)
	fmt.Fprintf(os.Stderr, "\nInspecting %s for %s --\n", kind, imgRef)
}

// PrintInspection outputs the details of the artifact (e.g., signature, attestation, sbom) to stdout for user inspection
func PrintInspection(
	ctx context.Context,
	imgRef string,
	signatures []oci.Signature,
	co *cosign.CheckOpts,
	output string,
) {
	switch output {
	case "text":
		for _, sig := range signatures {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				ce := cosign.CertExtensions{Cert: cert}
				fmt.Fprintln(os.Stderr, "Certificate subject: ", sigs.CertSubject(cert))
				if issuerURL := ce.GetIssuer(); issuerURL != "" {
					fmt.Fprintln(os.Stderr, "Certificate issuer URL: ", issuerURL)
				}

				if githubWorkflowTrigger := ce.GetCertExtensionGithubWorkflowTrigger(); githubWorkflowTrigger != "" {
					fmt.Fprintln(os.Stderr, "GitHub Workflow Trigger:", githubWorkflowTrigger)
				}

				if githubWorkflowSha := ce.GetExtensionGithubWorkflowSha(); githubWorkflowSha != "" {
					fmt.Fprintln(os.Stderr, "GitHub Workflow SHA:", githubWorkflowSha)
				}
				if githubWorkflowName := ce.GetCertExtensionGithubWorkflowName(); githubWorkflowName != "" {
					fmt.Fprintln(os.Stderr, "GitHub Workflow Name:", githubWorkflowName)
				}

				if githubWorkflowRepository := ce.GetCertExtensionGithubWorkflowRepository(); githubWorkflowRepository != "" {
					fmt.Fprintln(os.Stderr, "GitHub Workflow Trigger", githubWorkflowRepository)
				}

				if githubWorkflowRef := ce.GetCertExtensionGithubWorkflowRef(); githubWorkflowRef != "" {
					fmt.Fprintln(os.Stderr, "GitHub Workflow Ref:", githubWorkflowRef)
				}
			}

			p, err := sig.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}

			fmt.Println(string(p))

		}

	default:
		var outputKeys []payload.SimpleContainerImage
		for _, sig := range signatures {
			p, err := sig.Payload()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching payload: %v", err)
				return
			}

			ss := payload.SimpleContainerImage{}
			if err := json.Unmarshal(p, &ss); err != nil {
				fmt.Println("error decoding the payload:", err.Error())
				return
			}

			if cert, err := sig.Cert(); err == nil && cert != nil {
				ce := cosign.CertExtensions{Cert: cert}
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Subject"] = sigs.CertSubject(cert)
				if issuerURL := ce.GetIssuer(); issuerURL != "" {
					ss.Optional["Issuer"] = issuerURL
					ss.Optional[cosign.CertExtensionOIDCIssuer] = issuerURL
				}
				if githubWorkflowTrigger := ce.GetCertExtensionGithubWorkflowTrigger(); githubWorkflowTrigger != "" {
					ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowTrigger]] = githubWorkflowTrigger
					ss.Optional[cosign.CertExtensionGithubWorkflowTrigger] = githubWorkflowTrigger
				}

				if githubWorkflowSha := ce.GetExtensionGithubWorkflowSha(); githubWorkflowSha != "" {
					ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowSha]] = githubWorkflowSha
					ss.Optional[cosign.CertExtensionGithubWorkflowSha] = githubWorkflowSha
				}
				if githubWorkflowName := ce.GetCertExtensionGithubWorkflowName(); githubWorkflowName != "" {
					ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowName]] = githubWorkflowName
					ss.Optional[cosign.CertExtensionGithubWorkflowName] = githubWorkflowName
				}

				if githubWorkflowRepository := ce.GetCertExtensionGithubWorkflowRepository(); githubWorkflowRepository != "" {
					ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowRepository]] = githubWorkflowRepository
					ss.Optional[cosign.CertExtensionGithubWorkflowRepository] = githubWorkflowRepository
				}

				if githubWorkflowRef := ce.GetCertExtensionGithubWorkflowRef(); githubWorkflowRef != "" {
					ss.Optional[cosign.CertExtensionMap[cosign.CertExtensionGithubWorkflowRef]] = githubWorkflowRef
					ss.Optional[cosign.CertExtensionGithubWorkflowRef] = githubWorkflowRef
				}
			}
			if bundle, err := sig.Bundle(); err == nil && bundle != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Bundle"] = bundle
			}
			if rfc3161Timestamp, err := sig.RFC3161Timestamp(); err == nil &&
				rfc3161Timestamp != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["RFC3161Timestamp"] = rfc3161Timestamp
			}

			outputKeys = append(outputKeys, ss)

		}

		b, err := json.Marshal(outputKeys)
		if err != nil {
			fmt.Println("error when generating the output:", err.Error())
			return
		}

		fmt.Printf("\n%s\n", string(b))
		// TM: Commented out for now as not certain whether this is a desired functionality
		// if co.IgnoreTlog == false {
		// 	err := PrintTlogInspection(ctx, imgRef, signatures, co)
		// 	if err != nil {
		// 		fmt.Println("Error generating transparency log output:", err.Error())
		// 	}
		// }
	}
}
