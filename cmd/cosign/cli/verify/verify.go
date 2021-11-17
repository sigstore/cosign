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
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOptions
	CheckClaims   bool
	KeyRef        string
	CertEmail     string
	Sk            bool
	Slot          string
	Output        string
	RekorURL      string
	Attachment    string
	Annotations   sigs.AnnotationsMap
	SignatureRef  string
	HashAlgorithm crypto.Hash
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom", "":
		break
	default:
		return flag.ErrHelp
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	if !options.OneOf(c.KeyRef, c.Sk) && !options.EnableExperimental() {
		return &options.KeyParseError{}
	}
	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}
	co := &cosign.CheckOpts{
		Annotations:        c.Annotations.Annotations,
		RegistryClientOpts: ociremoteOpts,
		CertEmail:          c.CertEmail,
		SignatureRef:       c.SignatureRef,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.SimpleClaimVerifier
	}
	if options.EnableExperimental() {
		co.RekorURL = c.RekorURL
		co.RootCerts = fulcio.GetRoots()
	}
	keyRef := c.KeyRef

	// Keys are optional!
	var pubKey signature.Verifier
	if keyRef != "" {
		pubKey, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, c.HashAlgorithm)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	} else if c.Sk {
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "initializing piv token verifier")
		}
	}
	co.SigVerifier = pubKey

	for _, img := range images {
		ref, err := name.ParseReference(img)
		if err != nil {
			return errors.Wrap(err, "parsing reference")
		}
		ref, err = sign.GetAttachedImageRef(ref, c.Attachment, ociremoteOpts...)
		if err != nil {
			return errors.Wrapf(err, "resolving attachment type %s for image %s", c.Attachment, img)
		}

		verified, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
		if err != nil {
			return err
		}

		PrintVerificationHeader(ref.Name(), co, bundleVerified)
		PrintVerification(ref.Name(), verified, c.Output)
	}

	return nil
}

func PrintVerificationHeader(imgRef string, co *cosign.CheckOpts, bundleVerified bool) {
	fmt.Fprintf(os.Stderr, "\nVerification for %s --\n", imgRef)
	fmt.Fprintln(os.Stderr, "The following checks were performed on each of these signatures:")
	if co.ClaimVerifier != nil {
		if co.Annotations != nil {
			fmt.Fprintln(os.Stderr, "  - The specified annotations were verified.")
		}
		fmt.Fprintln(os.Stderr, "  - The cosign claims were validated")
	}
	if bundleVerified {
		fmt.Fprintln(os.Stderr, "  - Existence of the claims in the transparency log was verified offline")
	} else if co.RekorURL != "" {
		fmt.Fprintln(os.Stderr, "  - The claims were present in the transparency log")
		fmt.Fprintln(os.Stderr, "  - The signatures were integrated into the transparency log when the certificate was valid")
	}
	if co.SigVerifier != nil {
		fmt.Fprintln(os.Stderr, "  - The signatures were verified against the specified public key")
	}
	fmt.Fprintln(os.Stderr, "  - Any certificates were verified against the Fulcio roots.")
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(imgRef string, verified []oci.Signature, output string) {
	switch output {
	case "text":
		for _, sig := range verified {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				fmt.Println("Certificate subject: ", sigs.CertSubject(cert))
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					fmt.Println("Certificate issuer URL: ", issuerURL)
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
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Subject"] = sigs.CertSubject(cert)
				if issuerURL := sigs.CertIssuerExtension(cert); issuerURL != "" {
					ss.Optional["Issuer"] = issuerURL
				}
			}
			if bundle, err := sig.Bundle(); err == nil && bundle != nil {
				if ss.Optional == nil {
					ss.Optional = make(map[string]interface{})
				}
				ss.Optional["Bundle"] = bundle
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
