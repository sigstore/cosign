// Copyright 2026 The Sigstore Authors.
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
	"fmt"
	"time"

	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:               "cosign-lite",
		Short:             "cosign-lite is a lightweight Sigstore signing and verification utility",
		DisableAutoGenTag: true,
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(
		Initialize(),
		GenerateKeyPair(),
		Sign(),
		Attest(),
		Verify(),
		VerifyAttestation(),
	)

	return rootCmd
}

func Initialize() *cobra.Command {
	var mirror string
	var rootPath string
	var rootChecksum string
	var staging bool

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initialize TUF roots of trust",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			switch {
			case staging:
				return doInitializeStaging(ctx)
			case rootChecksum != "":
				return doInitializeWithRootChecksum(ctx, rootPath, mirror, rootChecksum)
			default:
				return doInitialize(ctx, rootPath, mirror)
			}
		},
	}

	cmd.Flags().StringVar(&mirror, "mirror", tufv1.DefaultRemoteRoot, "GCS bucket to a SigStore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap)")
	cmd.Flags().StringVar(&rootPath, "root", "", "path to trusted initial root. defaults to embedded root")
	cmd.Flags().StringVar(&rootChecksum, "root-checksum", "", "checksum of the initial root, required if root is downloaded via http(s). expects sha256 by default, can be changed to sha512 by providing sha512:<checksum>")
	cmd.Flags().BoolVar(&staging, "staging", false, "use the staging TUF repository")

	return cmd
}

func GenerateKeyPair() *cobra.Command {
	var outputKeyPrefix string

	cmd := &cobra.Command{
		Use:   "generate-key-pair",
		Short: "Generate a local password-encrypted key pair",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := generateKeyPair(outputKeyPrefix, getPass); err != nil {
				return err
			}
			fmt.Println("Private key written to", outputKeyPrefix+".key")
			fmt.Println("Public key written to", outputKeyPrefix+".pub")
			return nil
		},
	}

	cmd.Flags().StringVar(&outputKeyPrefix, "output-key-prefix", "cosign", "name used for generated .pub and .key files")

	return cmd
}

func Sign() *cobra.Command {
	var o SignOptions

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign the supplied payload blob.",
		Long: `Sign the supplied payload blob using a Sigstore OIDC identity token (keyless flow)
or a local on-disk key pair, and generate a standardized Sigstore verification bundle.`,
		Example: `  # Sign a payload keylessly using OIDC and write the bundle to a file
  cosign-lite sign --bundle payload.bundle.json payload.txt

  # Sign a payload using a local private key and write the bundle to a file
  cosign-lite sign --key cosign.key --bundle payload.bundle.json payload.txt

  # Sign a payload using OIDC without uploading to the transparency log (Rekor)
  cosign-lite sign --bundle payload.bundle.json --tlog-upload=false payload.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			ro, ko, err := o.ToRootAndKeyOpts(getPass)
			if err != nil {
				return err
			}

			return signBundle(cmd.Context(), ro, ko, payloadPath, o.CertPath, o.CertChainPath, o.TlogUpload, false)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func Attest() *cobra.Command {
	var o SignOptions

	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Attest the supplied in-toto statement.",
		Long: `Sign a pre-constructed in-toto statement JSON using a Sigstore OIDC identity token (keyless flow)
or a local on-disk key pair, wrapping it in a DSSE envelope, and generate a standardized Sigstore verification bundle.`,
		Example: `  # Sign a statement keylessly using OIDC and write the bundle to a file
  cosign-lite attest --bundle statement.bundle.json statement.json

  # Sign a statement using a local private key and write the bundle to a file
  cosign-lite attest --key cosign.key --bundle statement.bundle.json statement.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			ro, ko, err := o.ToRootAndKeyOpts(getPass)
			if err != nil {
				return err
			}

			return signBundle(cmd.Context(), ro, ko, payloadPath, o.CertPath, o.CertChainPath, o.TlogUpload, true)
		},
	}

	o.AddFlags(cmd)

	return cmd
}

func Verify() *cobra.Command {
	var vo VerifyOpts
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature on the supplied payload blob.",
		Long: `Verify the supplied payload blob against a standardized Sigstore verification bundle
using either a local public key or certificate identities loaded from the bundle.`,
		Example: `  # Verify a payload using a local public key
  cosign-lite verify --bundle payload.bundle.json --key cosign.pub payload.txt

  # Verify a payload keylessly using an OIDC identity subject and issuer
  cosign-lite verify --bundle payload.bundle.json \
    --certificate-identity "user@example.com" \
    --certificate-oidc-issuer "https://accounts.google.com" \
    payload.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payloadPath := args[0]

			if err := vo.Validate(); err != nil {
				return err
			}

			ctx := cmd.Context()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			return verifyBundle(ctx, vo, payloadPath, false)
		},
	}

	vo.AddFlags(cmd)
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

	return cmd
}

func VerifyAttestation() *cobra.Command {
	var vo VerifyOpts
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify-attestation",
		Short: "Verify an attestation on the supplied blob.",
		Long:  "Verify a signed in-toto statement wrapped in a DSSE envelope inside a standard Sigstore bundle.",
		Example: `  # Verify an attestation and assert it describes a specific payload file
  cosign-lite verify-attestation --bundle statement.bundle.json --key cosign.pub payload.txt

  # Verify the attestation signature without asserting it describes a specific file
  cosign-lite verify-attestation --bundle statement.bundle.json --key cosign.pub --check-claims=false`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var payloadPath string
			if len(args) > 0 {
				payloadPath = args[0]
			}

			if err := vo.Validate(); err != nil {
				return err
			}

			ctx := cmd.Context()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			return verifyBundle(ctx, vo, payloadPath, true)
		},
	}

	vo.AddFlags(cmd)
	cmd.Flags().StringVar(&vo.PredicateType, "predicate-type", "custom", "specify a predicate type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI")
	cmd.Flags().BoolVar(&vo.CheckClaims, "check-claims", true, "if true, verifies the digest exists in the in-toto subject (using either the provided digest and digest algorithm or the provided blob's sha256 digest). If false, only the DSSE envelope is verified.")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 3*time.Minute, "timeout for commands")

	return cmd
}
