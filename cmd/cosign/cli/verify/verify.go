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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	cosignError "github.com/sigstore/cosign/v3/cmd/cosign/errors"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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
	CertRef                      string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CAIntermediates              string
	CARoots                      string
	CertChain                    string
	CertOidcProvider             string
	IgnoreSCT                    bool
	SCTRef                       string
	Sk                           bool
	Slot                         string
	Output                       string
	RekorURL                     string
	Attachment                   string
	Annotations                  sigs.AnnotationsMap
	SignatureRef                 string
	PayloadRef                   string
	HashAlgorithm                crypto.Hash
	LocalImage                   bool
	NameOptions                  []name.Option
	Offline                      bool
	TSACertChainPath             string
	UseSignedTimestamps          bool
	IgnoreTlog                   bool
	MaxWorkers                   int
	ExperimentalOCI11            bool
	NewBundleFormat              bool
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom":
		fmt.Fprintln(os.Stderr, options.SBOMAttachmentDeprecation)
	case "":
		break
	default:
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
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
		Annotations:                  c.Annotations.Annotations,
		RegistryClientOpts:           ociremoteOpts,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		SignatureRef:                 c.SignatureRef,
		PayloadRef:                   c.PayloadRef,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		MaxWorkers:                   c.MaxWorkers,
		ExperimentalOCI11:            c.ExperimentalOCI11,
		UseSignedTimestamps:          c.TSACertChainPath != "" || c.UseSignedTimestamps,
		NewBundleFormat:              c.NewBundleFormat,
	}

	// Check to see if we are using the new bundle format or not
	if !c.LocalImage {
		ref, err := name.ParseReference(images[0], c.NameOptions...)
		if err == nil && c.NewBundleFormat {
			newBundles, _, err := cosign.GetBundles(ctx, ref, co)
			if len(newBundles) == 0 || err != nil {
				co.NewBundleFormat = false
			}
		}
	}

	err = SetTrustedMaterial(ctx, c.TrustedRootPath, c.CertChain, c.CARoots, c.CAIntermediates, c.TSACertChainPath, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	if err = CheckSigstoreBundleUnsupportedOptions(*c, co); err != nil {
		return err
	}

	if c.CheckClaims {
		co.ClaimVerifier = cosign.SimpleClaimVerifier
	}

	err = SetLegacyClientsAndKeys(ctx, c.IgnoreTlog, shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk), keylessVerification(c.KeyRef, c.Sk), c.RekorURL, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, co)
	if err != nil {
		return fmt.Errorf("setting up clients and keys: %w", err)
	}

	// Keys are optional!
	var closeSV func()
	co.SigVerifier, _, closeSV, err = LoadVerifierFromKeyOrCert(ctx, c.KeyRef, c.Slot, c.CertRef, c.CertChain, c.HashAlgorithm, c.Sk, false, co)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
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
	// 2. We’re going to find an x509 certificate on the signature and verify against
	//    Fulcio root trust (or user supplied root trust)
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, img := range images {
		var verified []oci.Signature
		var bundleVerified bool

		if c.LocalImage {
			if co.NewBundleFormat {
				verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, img, co)
				if err != nil {
					return err
				}
			} else {
				verified, bundleVerified, err = cosign.VerifyLocalImageSignatures(ctx, img, co)
				if err != nil {
					return err
				}
			}
			PrintVerificationHeader(ctx, img, co, bundleVerified, fulcioVerified)
			PrintVerification(ctx, verified, c.Output)
		} else {
			ref, err := name.ParseReference(img, c.NameOptions...)
			if err != nil {
				return fmt.Errorf("parsing reference: %w", err)
			}

			if co.NewBundleFormat {
				// OCI bundle always contains attestation
				verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co)
				if err != nil {
					return err
				}

				verifiedOutput, err := transformOutput(verified, ref.Name())
				if err == nil {
					verified = verifiedOutput
				}
			} else {
				ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
				if err != nil {
					return fmt.Errorf("resolving attachment type %s for image %s: %w", c.Attachment, img, err)
				}

				verified, bundleVerified, err = cosign.VerifyImageSignatures(ctx, ref, co)
				if err != nil {
					return cosignError.WrapError(err)
				}
			}

			PrintVerificationHeader(ctx, ref.Name(), co, bundleVerified, fulcioVerified)
			PrintVerification(ctx, verified, c.Output)
		}
	}

	return nil
}

func PrintVerificationHeader(ctx context.Context, imgRef string, co *cosign.CheckOpts, bundleVerified, fulcioVerified bool) {
	ui.Infof(ctx, "\nVerification for %s --", imgRef)
	ui.Infof(ctx, "The following checks were performed on each of these signatures:")
	if co.ClaimVerifier != nil {
		if co.Annotations != nil {
			ui.Infof(ctx, "  - The specified annotations were verified.")
		}
		ui.Infof(ctx, "  - The cosign claims were validated")
	}
	if bundleVerified {
		ui.Infof(ctx, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.RekorClient != nil {
		ui.Infof(ctx, "  - The claims were present in the transparency log")
		ui.Infof(ctx, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.SigVerifier != nil {
		ui.Infof(ctx, "  - The signatures were verified against the specified public key")
	}
	if fulcioVerified {
		ui.Infof(ctx, "  - The code-signing certificate was verified using trusted certificate authority certificates")
	}
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(ctx context.Context, verified []oci.Signature, output string) {
	switch output {
	case "text":
		for _, sig := range verified {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				ce := cosign.CertExtensions{Cert: cert}
				sub := ""
				if sans := cryptoutils.GetSubjectAlternateNames(cert); len(sans) > 0 {
					sub = sans[0]
				}
				ui.Infof(ctx, "Certificate subject: %s", sub)
				if issuerURL := ce.GetIssuer(); issuerURL != "" {
					ui.Infof(ctx, "Certificate issuer URL: %s", issuerURL)
				}

				if githubWorkflowTrigger := ce.GetCertExtensionGithubWorkflowTrigger(); githubWorkflowTrigger != "" {
					ui.Infof(ctx, "GitHub Workflow Trigger: %s", githubWorkflowTrigger)
				}

				if githubWorkflowSha := ce.GetExtensionGithubWorkflowSha(); githubWorkflowSha != "" {
					ui.Infof(ctx, "GitHub Workflow SHA: %s", githubWorkflowSha)
				}
				if githubWorkflowName := ce.GetCertExtensionGithubWorkflowName(); githubWorkflowName != "" {
					ui.Infof(ctx, "GitHub Workflow Name: %s", githubWorkflowName)
				}

				if githubWorkflowRepository := ce.GetCertExtensionGithubWorkflowRepository(); githubWorkflowRepository != "" {
					ui.Infof(ctx, "GitHub Workflow Repository: %s", githubWorkflowRepository)
				}

				if githubWorkflowRef := ce.GetCertExtensionGithubWorkflowRef(); githubWorkflowRef != "" {
					ui.Infof(ctx, "GitHub Workflow Ref: %s", githubWorkflowRef)
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
		for _, sig := range verified {
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
				sub := ""
				if sans := cryptoutils.GetSubjectAlternateNames(cert); len(sans) > 0 {
					sub = sans[0]
				}
				ss.Optional["Subject"] = sub
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
			if rfc3161Timestamp, err := sig.RFC3161Timestamp(); err == nil && rfc3161Timestamp != nil {
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
	}
}

func loadCertFromFileOrURL(path string) (*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	return loadCertFromPEM(pems)
}

func loadCertFromPEM(pems []byte) (*x509.Certificate, error) {
	var out []byte
	out, err := base64.StdEncoding.DecodeString(string(pems))
	if err != nil {
		// not a base64
		out = pems
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(out)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem file")
	}
	return certs[0], nil
}

func loadCertChainFromFileOrURL(path string) ([]*x509.Certificate, error) {
	pems, err := blob.LoadFileOrURL(path)
	if err != nil {
		return nil, err
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(pems))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func keylessVerification(keyRef string, sk bool) bool {
	if keyRef != "" {
		return false
	}
	if sk {
		return false
	}
	return true
}

func shouldVerifySCT(ignoreSCT bool, keyRef string, sk bool) bool {
	if keyRef != "" {
		return false
	}
	if sk {
		return false
	}
	if ignoreSCT {
		return false
	}
	return true
}

// loadCertsKeylessVerification loads certificates provided as a certificate chain or CA roots + CA intermediate
// certificate files. If both certChain and caRootsFile are empty strings, the Fulcio roots are loaded.
//
// The co *cosign.CheckOpts is both input and output parameter - it gets updated
// with the root and intermediate certificates needed for verification.
func loadCertsKeylessVerification(certChainFile string,
	caRootsFile string,
	caIntermediatesFile string,
	co *cosign.CheckOpts) error {
	var err error
	switch {
	case certChainFile != "":
		chain, err := loadCertChainFromFileOrURL(certChainFile)
		if err != nil {
			return err
		}
		co.RootCerts = x509.NewCertPool()
		co.RootCerts.AddCert(chain[len(chain)-1])
		if len(chain) > 1 {
			co.IntermediateCerts = x509.NewCertPool()
			for _, cert := range chain[:len(chain)-1] {
				co.IntermediateCerts.AddCert(cert)
			}
		}
	case caRootsFile != "":
		caRoots, err := loadCertChainFromFileOrURL(caRootsFile)
		if err != nil {
			return err
		}
		co.RootCerts = x509.NewCertPool()
		if len(caRoots) > 0 {
			for _, cert := range caRoots {
				co.RootCerts.AddCert(cert)
			}
		}
		if caIntermediatesFile != "" {
			caIntermediates, err := loadCertChainFromFileOrURL(caIntermediatesFile)
			if err != nil {
				return err
			}
			if len(caIntermediates) > 0 {
				co.IntermediateCerts = x509.NewCertPool()
				for _, cert := range caIntermediates {
					co.IntermediateCerts.AddCert(cert)
				}
			}
		}
	default:
		// This performs an online fetch of the Fulcio roots from a TUF repository.
		// This is needed for verifying keyless certificates (both online and offline).
		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("getting Fulcio intermediates: %w", err)
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
		var intotoStatement in_toto.StatementHeader
		err = json.Unmarshal(dsseEnvelope.Payload, &intotoStatement)
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
