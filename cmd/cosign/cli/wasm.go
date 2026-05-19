//
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/wasm"
	"github.com/spf13/cobra"
)

func Wasm() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wasm",
		Short: "Utilities for working with WebAssembly modules and embedded wasm-cosign signatures",
	}

	cmd.AddCommand(wasmSign())
	cmd.AddCommand(wasmVerify())
	cmd.AddCommand(wasmListSignatures())
	cmd.AddCommand(wasmExtractSignatures())
	cmd.AddCommand(wasmStripSignatures())
	return cmd
}

func wasmSign() *cobra.Command {
	o := &options.SignBlobOptions{}

	cmd := &cobra.Command{
		Use:   "sign <module>",
		Short: "Sign a WebAssembly module with an embedded wasm-cosign custom section",
		Example: `  cosign wasm sign --wasm-output signed.wasm --key cosign.key module.wasm

  # append another wasm-cosign custom section to an already signed module
  cosign wasm sign --wasm-output resigned.wasm --key cosign.key module.wasm`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if options.NOf(o.Key, o.SecurityKey.Use) > 1 {
				return &options.KeyParseError{}
			}
			if o.WasmOutput == "" {
				return fmt.Errorf("--wasm-output is required")
			}
			if o.WasmOutput != "" && !o.NewBundleFormat {
				return fmt.Errorf("--wasm-output requires --new-bundle-format")
			}

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
				SigningAlgorithm:               o.SigningAlgorithm,
			}
			if err := signcommon.LoadTrustedMaterialAndSigningConfig(cmd.Context(), &ko, o.UseSigningConfig, o.SigningConfigPath,
				o.Rekor.URL, o.Fulcio.URL, o.OIDC.Issuer, o.TSAServerURL, o.TrustedRootPath, o.TlogUpload,
				o.NewBundleFormat, o.BundlePath, o.Key, o.IssueCertificate,
				o.Output, "", o.OutputCertificate, "", o.OutputSignature, o.RFC3161TimestampPath); err != nil {
				return err
			}

			if err := signWasmBlob(cmd.Context(), ko, args[0], o.Cert, o.CertChain, o.Base64Output, o.OutputSignature, o.OutputCertificate, o.TlogUpload, o.WasmOutput); err != nil {
				return fmt.Errorf("signing wasm %s: %w", args[0], err)
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	_ = cmd.Flags().MarkHidden("wasm")
	_ = cmd.MarkFlagRequired("wasm-output")
	return cmd
}

func wasmVerify() *cobra.Command {
	o := &options.VerifyBlobOptions{}

	cmd := &cobra.Command{
		Use:   "verify <module>",
		Short: "Verify a WebAssembly module with embedded wasm-cosign signatures",
		Example: `  cosign wasm verify --key cosign.pub module.wasm

  # verify all embedded wasm-cosign signatures in a module
  cosign wasm verify --key cosign.pub module.wasm`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.CommonVerifyOptions.PrivateInfrastructure {
				o.CommonVerifyOptions.IgnoreTlog = true
			}

			hashAlgorithm, err := o.SignatureDigest.HashAlgorithm()
			if err != nil {
				return err
			}
			verifyBlobCmd := newVerifyBlobCmd(o, hashAlgorithm)
			verifyBlobCmd.Wasm = true

			ctx, cancel := context.WithTimeout(cmd.Context(), ro.Timeout)
			defer cancel()

			if o.CommonVerifyOptions.IgnoreTlog && !o.CommonVerifyOptions.PrivateInfrastructure {
				ui.Warnf(ctx, ignoreTLogMessage, "blob")
			}

			return verifyBlobCmd.Exec(ctx, args[0])
		},
	}

	o.AddFlags(cmd)
	_ = cmd.Flags().MarkHidden("wasm")
	return cmd
}

func wasmExtractSignatures() *cobra.Command {
	cmd := &cobra.Command{
		Use:              "extract-signatures <module>",
		Short:            "Print embedded wasm-cosign bundle payloads from a WebAssembly module",
		Example:          `  cosign wasm extract-signatures module.wasm`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(_ *cobra.Command, args []string) error {
			return extractWasmSignatures(args[0])
		},
	}
	return cmd
}

func wasmListSignatures() *cobra.Command {
	o := &options.WasmListSignaturesOptions{}

	cmd := &cobra.Command{
		Use:   "list-signatures <module>",
		Short: "List embedded wasm-cosign signatures in a WebAssembly module",
		Example: `  cosign wasm list-signatures module.wasm

  # emit machine-readable signature metadata
  cosign wasm list-signatures -o json module.wasm`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(_ *cobra.Command, args []string) error {
			return listWasmSignatures(args[0], o.Output)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func wasmStripSignatures() *cobra.Command {
	o := &options.WasmStripSignaturesOptions{}

	cmd := &cobra.Command{
		Use:   "strip-signatures <module>",
		Short: "Remove embedded wasm-cosign custom sections from a WebAssembly module",
		Example: `  cosign wasm strip-signatures -o unsigned.wasm signed.wasm

  # read from stdin and write the stripped module to stdout
  cosign wasm strip-signatures -o - < signed.wasm`,
		Args:             cobra.ExactArgs(1),
		PersistentPreRun: options.BindViper,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := stripWasmSignatures(args[0], o.Output); err != nil {
				return err
			}
			if o.Output != "-" {
				ui.Infof(cmd.Context(), "Wrote unsigned wasm module to file %s", o.Output)
			}
			return nil
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func extractWasmSignatures(inPath string) error {
	module, err := readWasmModule(inPath)
	if err != nil {
		return err
	}

	_, sections, err := wasm.StripAndExtractSignatureSections(module)
	if err != nil {
		return err
	}

	for i, section := range sections {
		if i > 0 {
			if _, err := os.Stdout.Write([]byte("\n")); err != nil {
				return err
			}
		}
		if _, err := os.Stdout.Write(section); err != nil {
			return err
		}
	}
	return nil
}

type wasmSignatureInfo struct {
	Index       int    `json:"index"`
	Offset      int    `json:"offset"`
	SectionSize uint32 `json:"sectionSize"`
	PayloadSize int    `json:"payloadSize"`
	SHA256      string `json:"sha256"`
}

func listWasmSignatures(inPath, output string) error {
	module, err := readWasmModule(inPath)
	if err != nil {
		return err
	}

	sections, err := wasm.InspectSignatureSections(module)
	if err != nil {
		return err
	}

	infos := make([]wasmSignatureInfo, 0, len(sections))
	for _, section := range sections {
		digest := sha256.Sum256(section.Payload)
		infos = append(infos, wasmSignatureInfo{
			Index:       section.Index,
			Offset:      section.Offset,
			SectionSize: section.SectionSize,
			PayloadSize: section.PayloadSize,
			SHA256:      hex.EncodeToString(digest[:]),
		})
	}

	switch output {
	case "", "text":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "INDEX\tOFFSET\tSECTION SIZE\tPAYLOAD SIZE\tSHA256"); err != nil {
			return err
		}
		for _, info := range infos {
			if _, err := fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%s\n", info.Index, info.Offset, info.SectionSize, info.PayloadSize, info.SHA256); err != nil {
				return err
			}
		}
		return w.Flush()
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(infos)
	default:
		return fmt.Errorf("unknown output format %q, expected json or text", output)
	}
}

func stripWasmSignatures(inPath, outPath string) error {
	module, err := readWasmModule(inPath)
	if err != nil {
		return err
	}

	stripped, err := wasm.StripSignatureSections(module)
	if err != nil {
		return err
	}

	if outPath == "-" {
		_, err = os.Stdout.Write(stripped)
		return err
	}

	if err := os.WriteFile(filepath.Clean(outPath), stripped, 0600); err != nil {
		return fmt.Errorf("writing unsigned wasm module: %w", err)
	}
	return nil
}
