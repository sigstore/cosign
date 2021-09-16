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

package cli

import (
	"context"
	"flag"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
type VerifyAttestationCommand struct {
	CheckClaims bool
	KeyRef      string
	Sk          bool
	Slot        string
	Output      string
	FulcioURL   string
	RekorURL    string
}

func applyVerifyAttestationFlags(cmd *VerifyAttestationCommand, flagset *flag.FlagSet) {
	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, KMS URI or Kubernetes Secret")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.StringVar(&cmd.Slot, "slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
	flagset.BoolVar(&cmd.CheckClaims, "check-claims", true, "whether to check the claims found")
	flagset.StringVar(&cmd.FulcioURL, "fulcio-url", "https://fulcio.sigstore.dev", "[EXPERIMENTAL] address of sigstore PKI server")
	flagset.StringVar(&cmd.RekorURL, "rekor-url", "https://rekor.sigstore.dev", "[EXPERIMENTAL] address of rekor STL server")
}

// Verify builds and returns an ffcli command
func VerifyAttestation() *ffcli.Command {
	cmd := VerifyAttestationCommand{}
	flagset := flag.NewFlagSet("cosign verify-attestation", flag.ExitOnError)
	applyVerifyAttestationFlags(&cmd, flagset)

	return &ffcli.Command{
		Name:       "verify-attestation",
		ShortUsage: "cosign verify-attestation -key <key path>|<key url>|<kms uri> <image uri> [<image uri> ...]",
		ShortHelp:  "Verify an attestation on the supplied container image",
		LongHelp: `Verify an attestation on an image by checking the claims
against the transparency log.

EXAMPLES
  # verify cosign attestations on the image
  cosign verify-attestation <IMAGE>

  # verify multiple images
  cosign verify-attestation <IMAGE_1> <IMAGE_2> ...

  # additionally verify specified annotations
  cosign verify-attestation -a key1=val1 -a key2=val2 <IMAGE>

  # (experimental) additionally, verify with the transparency log
  COSIGN_EXPERIMENTAL=1 cosign verify-attestation <IMAGE>

  # verify image with public key
  cosign verify-attestation -key cosign.pub <IMAGE>

  # verify image with public key provided by URL
  cosign verify-attestation -key https://host.for/<FILE> <IMAGE>

  # verify image with public key stored in Google Cloud KMS
  cosign verify-attestation -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> <IMAGE>
  
  # verify image with public key stored in Hashicorp Vault
  cosign verify-attestation -key hashivault:///<KEY> <IMAGE>`,

		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// DSSE messages contain the signature and payload in one object, but our interface expects a signature and payload
// This means we need to use one field and ignore the other. The DSSE verifier upstream uses the signature field and ignores
// The message field, but we want the reverse here.
type reverseDSSEVerifier struct {
	signature.Verifier
}

func (w *reverseDSSEVerifier) VerifySignature(s io.Reader, m io.Reader, opts ...signature.VerifyOption) error {
	return w.Verifier.VerifySignature(m, nil, opts...)
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, args []string) (err error) {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	if !oneOf(c.KeyRef, c.Sk) && !EnableExperimental() {
		return &KeyParseError{}
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts:   DefaultRegistryClientOpts(ctx),
		SigTagSuffixOverride: cosign.AttestationTagSuffix,
	}
	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}
	if EnableExperimental() {
		co.RekorURL = c.RekorURL
		co.RootCerts = fulcio.GetRoots()
	}
	keyRef := c.KeyRef

	// Keys are optional!
	var pubKey signature.Verifier
	if keyRef != "" {
		pubKey, err = publicKeyFromKeyRef(ctx, keyRef)
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

	co.SigVerifier = &reverseDSSEVerifier{
		Verifier: dsse.WrapVerifier(pubKey),
	}

	for _, imageRef := range args {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return err
		}
		sigRepo, err := TargetRepositoryForImage(ref)
		if err != nil {
			return err
		}
		co.SignatureRepo = sigRepo
		//TODO: this is really confusing, it's actually a return value for the printed verification below
		co.VerifyBundle = false

		verified, err := cosign.Verify(ctx, ref, co)
		if err != nil {
			return err
		}

		PrintVerificationHeader(imageRef, co)
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion
		PrintVerification(imageRef, verified, "text")
	}

	return nil
}
