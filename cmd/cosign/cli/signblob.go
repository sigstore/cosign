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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/wasm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func SignBlob() *cobra.Command {
	o := &options.SignBlobOptions{}
	viper.RegisterAlias("output", "output-signature")

	cmd := &cobra.Command{
		Use:   "sign-blob",
		Short: "Sign the supplied blob, outputting the base64-encoded signature to stdout.",
		Example: `  cosign sign-blob --key <key path>|<kms uri> <blob>

  # sign a blob with a local key pair file
  cosign sign-blob --key cosign.key <FILE>

  # sign a blob with a key stored in an environment variable
  cosign sign-blob --key env://[ENV_VAR] <FILE>

  # sign a blob with a key pair stored in Azure Key Vault
  cosign sign-blob --key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <FILE>

  # sign a blob with a key pair stored in AWS KMS
  cosign sign-blob --key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <FILE>

  # sign a blob with a key pair stored in Google Cloud KMS
  cosign sign-blob --key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY] <FILE>

  # sign a blob with a key pair stored in Hashicorp Vault
  cosign sign-blob --key hashivault://[KEY] <FILE>

  # sign a WebAssembly module, appending the Sigstore bundle in a new wasm-cosign custom section
  cosign sign-blob --wasm --wasm-output signed.wasm --key cosign.key module.wasm`,
		Args:             cobra.MinimumNArgs(1),
		PersistentPreRun: options.BindViper,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if options.NOf(o.Key, o.SecurityKey.Use) > 1 {
				return &options.KeyParseError{}
			}

			if o.WasmOutput != "" {
				o.Wasm = true
			}
			if o.WasmOutput != "" && len(args) != 1 {
				return fmt.Errorf("--wasm-output can only be used when signing exactly one wasm module")
			}
			if o.WasmOutput != "" && !o.NewBundleFormat {
				return fmt.Errorf("--wasm-output requires --new-bundle-format")
			}
			if o.NewBundleFormat && o.BundlePath == "" && o.WasmOutput == "" {
				return fmt.Errorf("must specify --bundle with --new-bundle-format")
			}

			// Check if the algorithm is in the list of supported algorithms
			supportedAlgorithms := cosign.GetSupportedAlgorithms()
			isValid := false
			for _, algo := range supportedAlgorithms {
				if algo == o.SigningAlgorithm {
					isValid = true
					break
				}
			}
			if !isValid {
				return fmt.Errorf("invalid signing algorithm: %s. Supported algorithms are: %s",
					o.SigningAlgorithm, strings.Join(supportedAlgorithms, ", "))
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			signingAlgorithm := ""
			if cmd.Flags().Changed("signing-algorithm") {
				signingAlgorithm = o.SigningAlgorithm
			}
			oidcClientSecret, err := o.OIDC.ClientSecret()
			if err != nil {
				return err
			}

			ko := options.KeyOpts{
				KeyRef:                         o.Key,
				PassFunc:                       generate.GetPass,
				Sk:                             o.SecurityKey.Use,
				Slot:                           o.SecurityKey.Slot,
				FulcioURL:                      o.Fulcio.URL,
				IDToken:                        o.Fulcio.IdentityToken,
				FulcioAuthFlow:                 o.Fulcio.AuthFlow,
				InsecureSkipFulcioVerify:       o.Fulcio.InsecureSkipFulcioVerify,
				RekorURL:                       o.Rekor.URL,
				OIDCIssuer:                     o.OIDC.Issuer,
				OIDCClientID:                   o.OIDC.ClientID,
				OIDCClientSecret:               oidcClientSecret,
				OIDCRedirectURL:                o.OIDC.RedirectURL,
				OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
				BundlePath:                     o.BundlePath,
				NewBundleFormat:                o.NewBundleFormat,
				SkipConfirmation:               o.SkipConfirmation,
				TSAClientCACert:                o.TSAClientCACert,
				TSAClientCert:                  o.TSAClientCert,
				TSAClientKey:                   o.TSAClientKey,
				TSAServerName:                  o.TSAServerName,
				TSAServerURL:                   o.TSAServerURL,
				RFC3161TimestampPath:           o.RFC3161TimestampPath,
				IssueCertificateForExistingKey: o.IssueCertificate,
				SigningAlgorithm:               signingAlgorithm,
			}
			if err := signcommon.LoadTrustedMaterialAndSigningConfig(cmd.Context(), &ko, o.UseSigningConfig, o.SigningConfigPath,
				o.Rekor.URL, o.Fulcio.URL, o.OIDC.Issuer, o.TSAServerURL, o.TrustedRootPath, o.TlogUpload,
				o.NewBundleFormat, o.BundlePath, o.Key, o.IssueCertificate,
				o.Output, "", o.OutputCertificate, "", o.OutputSignature, o.RFC3161TimestampPath); err != nil {
				return err
			}

			for _, blob := range args {
				// TODO: remove when the output flag has been deprecated
				if o.Output != "" {
					fmt.Fprintln(os.Stderr, "WARNING: the '--output' flag is deprecated and will be removed in the future. Use '--output-signature'")
					o.OutputSignature = o.Output
				}

				if o.Wasm {
					if err := signWasmBlob(cmd.Context(), ko, blob, o.Cert, o.CertChain, o.Base64Output, o.OutputSignature, o.OutputCertificate, o.TlogUpload, o.WasmOutput); err != nil {
						return fmt.Errorf("signing wasm %s: %w", blob, err)
					}
					continue
				}

				if _, err := sign.SignBlobCmd(cmd.Context(), ro, ko, blob, o.Cert, o.CertChain, o.Base64Output, o.OutputSignature, o.OutputCertificate, o.TlogUpload); err != nil {
					return fmt.Errorf("signing %s: %w", blob, err)
				}
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func signWasmBlob(ctx context.Context, ko options.KeyOpts, blobPath, certPath, certChainPath string, b64 bool, outputSignature, outputCertificate string, tlogUpload bool, wasmOutput string) error {
	module, err := readWasmModule(blobPath)
	if err != nil {
		return err
	}

	unsignedModule, err := wasm.StripSignatureSections(module)
	if err != nil {
		return err
	}

	payloadPath, cleanupPayload, err := writeTempFile("cosign-wasm-payload-*", unsignedModule)
	if err != nil {
		return err
	}
	defer cleanupPayload()

	bundlePath := ko.BundlePath
	var cleanupBundle func()
	if wasmOutput != "" && bundlePath == "" {
		bundlePath, cleanupBundle, err = writeTempFile("cosign-wasm-bundle-*.json", nil)
		if err != nil {
			return err
		}
		defer cleanupBundle()
		ko.BundlePath = bundlePath
	}

	if _, err := sign.SignBlobCmd(ctx, ro, ko, payloadPath, certPath, certChainPath, b64, outputSignature, outputCertificate, tlogUpload); err != nil {
		return err
	}

	if wasmOutput == "" {
		return nil
	}

	bundleBytes, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("reading bundle for wasm custom section: %w", err)
	}
	signedModule, err := wasm.AppendSignatureSection(module, bundleBytes)
	if err != nil {
		return err
	}
	if wasmOutput == "-" {
		_, err = os.Stdout.Write(signedModule)
		return err
	}
	if err := os.WriteFile(filepath.Clean(wasmOutput), signedModule, 0600); err != nil {
		return fmt.Errorf("writing signed wasm module: %w", err)
	}
	ui.Infof(ctx, "Wrote signed wasm module to file %s", wasmOutput)
	return nil
}

func readWasmModule(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(filepath.Clean(path))
}

func writeTempFile(pattern string, contents []byte) (string, func(), error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() {
		_ = os.Remove(name)
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}
