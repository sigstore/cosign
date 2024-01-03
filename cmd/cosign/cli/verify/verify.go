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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	cosignError "github.com/sigstore/cosign/v2/cmd/cosign/errors"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
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
	IgnoreTlog                   bool
	MaxWorkers                   int
	ExperimentalOCI11            bool
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
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.SimpleClaimVerifier
	}

	if c.TSACertChainPath != "" {
		_, err := os.Stat(c.TSACertChainPath)
		if err != nil {
			return fmt.Errorf("unable to open timestamp certificate chain file: %w", err)
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
		if c.CertChain != "" {
			chain, err := loadCertChainFromFileOrURL(c.CertChain)
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
		} else {
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
	}
	keyRef := c.KeyRef
	certRef := c.CertRef

	// Ignore Signed Certificate Timestamp if the flag is set or a key is provided
	if shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk) {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	// Keys are optional!
	var pubKey signature.Verifier
	switch {
	case keyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, c.HashAlgorithm)
		if err != nil {
			return fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("initializing piv token verifier: %w", err)
		}
	case certRef != "":
		cert, err := loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return err
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
			pubKey, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return err
			}
		} else {
			// Verify certificate with chain
			chain, err := loadCertChainFromFileOrURL(c.CertChain)
			if err != nil {
				return err
			}
			pubKey, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return err
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
	co.SigVerifier = pubKey

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We’re going to find an x509 certificate on the signature and verify against
	//    Fulcio root trust (or user supplied root trust)
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	for _, img := range images {
		if c.LocalImage {
			verified, bundleVerified, err := cosign.VerifyLocalImageSignatures(ctx, img, co)
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
			ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
			if err != nil {
				return fmt.Errorf("resolving attachment type %s for image %s: %w", c.Attachment, img, err)
			}

			verified, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
			if err != nil {
				return cosignError.WrapError(err)
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
