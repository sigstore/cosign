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
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/oci"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOpts
	CheckClaims bool
	KeyRef      string
	CertEmail   string
	Sk          bool
	Slot        string
	Output      string
	RekorURL    string
	Attachment  string
	Annotations *map[string]interface{}
}

func ApplyVerifyFlags(cmd *VerifyCommand, flagset *flag.FlagSet) {
	annotations := sigs.AnnotationsMap{}
	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, KMS URI or Kubernetes Secret")
	flagset.StringVar(&cmd.CertEmail, "cert-email", "", "the email expected in a valid fulcio cert")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.StringVar(&cmd.Slot, "slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
	flagset.StringVar(&cmd.RekorURL, "rekor-url", "https://rekor.sigstore.dev", "address of rekor STL server")
	flagset.BoolVar(&cmd.CheckClaims, "check-claims", true, "whether to check the claims found")
	flagset.StringVar(&cmd.Output, "output", "json", "output format for the signing image information (default JSON) (json|text)")
	flagset.StringVar(&cmd.Attachment, "attachment", "", "related image attachment to sign (none|sbom), default none")
	options.ApplyRegistryFlags(&cmd.RegistryOpts, flagset)

	// parse annotations
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	cmd.Annotations = &annotations.Annotations
}

// Verify builds and returns an ffcli command
func Verify() *ffcli.Command {
	cmd := VerifyCommand{}
	flagset := flag.NewFlagSet("cosign verify", flag.ExitOnError)
	ApplyVerifyFlags(&cmd, flagset)

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "cosign verify -key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]",
		ShortHelp:  "Verify a signature on the supplied container image",
		LongHelp: `Verify signature and annotations on an image by checking the claims
against the transparency log.

EXAMPLES
  # verify cosign claims and signing certificates on the image
  cosign verify <IMAGE>

  # verify multiple images
  cosign verify <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify <IMAGE>

  # verify image with public key
  cosign verify -key cosign.pub <IMAGE>

  # verify image with public key provided by URL
  cosign verify -key https://host.for/[FILE] <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <IMAGE>

  # verify image with public key stored in Hashicorp Vault
  cosign verify -key hashivault://[KEY] <IMAGE>

  # verify image with public key stored in a Kubernetes secret
  cosign verify -key k8s://[NAMESPACE]/[KEY] <IMAGE>`,

		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *VerifyCommand) Exec(ctx context.Context, args []string) (err error) {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	switch c.Attachment {
	case "sbom", "":
		break
	default:
		return flag.ErrHelp
	}

	if !options.OneOf(c.KeyRef, c.Sk) && !options.EnableExperimental() {
		return &options.KeyParseError{}
	}

	co := &cosign.CheckOpts{
		Annotations:        *c.Annotations,
		RegistryClientOpts: c.RegistryOpts.ClientOpts(ctx),
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
		pubKey, err = sigs.PublicKeyFromKeyRef(ctx, keyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
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

	for _, img := range args {
		ref, err := sign.GetAttachedImageRef(img, c.Attachment, c.RegistryOpts.GetRegistryClientOpts(ctx)...)
		if err != nil {
			return errors.Wrapf(err, "resolving attachment type %s for image %s", c.Attachment, img)
		}

		verified, bundleVerified, err := cosign.Verify(ctx, ref, co)
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

func certSubject(c *x509.Certificate) string {
	switch {
	case c.EmailAddresses != nil:
		return c.EmailAddresses[0]
	case c.URIs != nil:
		return c.URIs[0].String()
	}
	return ""
}

// PrintVerification logs details about the verification to stdout
func PrintVerification(imgRef string, verified []oci.Signature, output string) {
	switch output {
	case "text":
		for _, sig := range verified {
			if cert, err := sig.Cert(); err == nil && cert != nil {
				fmt.Println("Certificate subject: ", certSubject(cert))
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
				ss.Optional["Subject"] = certSubject(cert)
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
