// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"os"
	"reflect"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/cosign/v3/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v3/pkg/oci"
	csignature "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// CheckSigstoreBundleUnsupportedOptions checks for incompatible settings on any Verify* command struct when NewBundleFormat is used.
func CheckSigstoreBundleUnsupportedOptions(cmd any, verifyOfflineWithKey bool, co *cosign.CheckOpts) error {
	if !co.NewBundleFormat {
		return nil
	}
	fieldToErr := map[string]string{
		"CertRef":              "certificate must be in bundle and may not be provided using --certificate",
		"CertChain":            "certificate chain must be in bundle and may not be provided using --certificate-chain",
		"CARoots":              "CA roots/intermediates must be provided using --trusted-root",
		"CAIntermedias":        "CA roots/intermediates must be provided using --trusted-root",
		"TSACertChainPath":     "TSA certificate chain path may only be provided using --trusted-root",
		"RFC3161TimestampPath": "RFC3161 timestamp may not be provided using --rfc3161-timestamp",
		"SigRef":               "signature may not be provided using --signature",
		"SCTRef":               "SCT may not be provided using --sct",
	}
	v := reflect.ValueOf(cmd)
	for f, e := range fieldToErr {
		if field := v.FieldByName(f); field.IsValid() && field.String() != "" {
			return fmt.Errorf("unsupported: %s when using --new-bundle-format", e)
		}
	}
	if co.TrustedMaterial == nil && !verifyOfflineWithKey {
		return fmt.Errorf("trusted root is required when using new bundle format")
	}
	return nil
}

// LoadVerifierFromKeyOrCert returns either a signature.Verifier or a certificate from the provided flags to use for verifying an artifact.
// In the case of certain types of keys, it returns a close function that must be called by the calling method.
func LoadVerifierFromKeyOrCert(ctx context.Context, keyRef, slot, certRef, certChain string, hashAlgorithm crypto.Hash, sk, withGetCert bool, co *cosign.CheckOpts) (signature.Verifier, *x509.Certificate, func(), error) {
	var sigVerifier signature.Verifier
	var err error
	switch {
	case keyRef != "":
		sigVerifier, err = csignature.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, hashAlgorithm)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := sigVerifier.(*pkcs11key.Key)
		closeSV := func() {}
		if ok {
			closeSV = pkcs11Key.Close
		}
		return sigVerifier, nil, closeSV, nil
	case sk:
		sk, err := pivkey.GetKeyWithSlot(slot)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("opening piv token: %w", err)
		}
		sigVerifier, err = sk.Verifier()
		if err != nil {
			sk.Close()
			return nil, nil, nil, fmt.Errorf("initializing piv token verifier: %w", err)
		}
		return sigVerifier, nil, sk.Close, nil
	case certRef != "":
		cert, err := loadCertFromFileOrURL(certRef)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading cert: %w", err)
		}
		if withGetCert {
			return nil, cert, func() {}, nil
		}
		if certChain == "" {
			sigVerifier, err = cosign.ValidateAndUnpackCert(cert, co)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("validating cert: %w", err)
			}
			return sigVerifier, nil, func() {}, nil
		}
		chain, err := loadCertChainFromFileOrURL(certChain)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading cert chain: %w", err)
		}
		sigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("validating cert with chain: %w", err)
		}
		return sigVerifier, nil, func() {}, nil
	}
	return nil, nil, func() {}, nil
}

// SetLegacyClientsAndKeys sets up TSA and rekor clients and keys for TSA, rekor, and CT log.
// It may perform an online fetch of keys, so using trusted root instead of these TUF v1 methods is recommended.
// It takes a CheckOpts as input and modifies it.
func SetLegacyClientsAndKeys(ctx context.Context, ignoreTlog, shouldVerifySCT, keylessVerification bool, rekorURL, tsaCertChain, certChain, caRoots, caIntermediates string, co *cosign.CheckOpts) error {
	var err error
	if !ignoreTlog && !co.NewBundleFormat && rekorURL != "" {
		co.RekorClient, err = rekor.NewClient(rekorURL)
		if err != nil {
			return fmt.Errorf("creating rekor client: %w", err)
		}
	}
	// If trusted material is set, we don't need to fetch disparate keys.
	if co.TrustedMaterial != nil {
		return nil
	}
	if co.UseSignedTimestamps {
		tsaCertificates, err := cosign.GetTSACerts(ctx, tsaCertChain, cosign.GetTufTargets)
		if err != nil {
			return fmt.Errorf("loading TSA certificates: %w", err)
		}
		co.TSACertificate = tsaCertificates.LeafCert
		co.TSARootCertificates = tsaCertificates.RootCert
		co.TSAIntermediateCertificates = tsaCertificates.IntermediateCerts
	}
	if !ignoreTlog {
		co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting rekor public keys: %w", err)
		}
	}
	if shouldVerifySCT {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}
	if keylessVerification {
		if err := loadCertsKeylessVerification(certChain, caRoots, caIntermediates, co); err != nil {
			return fmt.Errorf("loading certs for keyless verification: %w", err)
		}
	}
	return nil
}

// SetTrustedMaterial sets TrustedMaterial on CheckOpts, either from the provided trusted root path or from TUF.
// It does not set TrustedMaterial if the user provided trusted material via other flags or environment variables.
func SetTrustedMaterial(ctx context.Context, trustedRootPath, certChain, caRoots, caIntermediates, tsaCertChainPath string, verifyOnlyWithKey bool, co *cosign.CheckOpts) error {
	var err error
	if trustedRootPath != "" {
		co.TrustedMaterial, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return fmt.Errorf("loading trusted root: %w", err)
		}
		return nil
	}
	if verifyOnlyWithKey {
		return nil
	}
	if options.NOf(certChain, caRoots, caIntermediates, tsaCertChainPath) == 0 &&
		env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "" &&
		env.Getenv(env.VariableSigstoreRootFile) == "" &&
		env.Getenv(env.VariableSigstoreRekorPublicKey) == "" &&
		env.Getenv(env.VariableSigstoreTSACertificateFile) == "" {
		co.TrustedMaterial, err = cosign.TrustedRoot()
		if err != nil {
			ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
		}
	}
	return nil
}

// PrintVerificationHeader prints boilerplate information after successful verification.
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

// PrintVerification logs details about the verification to stdout.
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

// No trusted root is needed if verification doesn't require Rekor or
// signed timestamps, and a key is explicitly provided instead of using
// a Fulcio certificate either via a key or certificate reference or security key.
func verifyOfflineWithKey(keyRef, certRef string, sk bool, co *cosign.CheckOpts) bool {
	return (keyRef != "" || certRef != "" || sk) && co.IgnoreTlog && !co.UseSignedTimestamps
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
