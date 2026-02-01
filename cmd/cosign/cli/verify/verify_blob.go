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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
type VerifyBlobCmd struct {
	options.KeyOpts
	options.CertVerifyOptions
	CertRef                      string
	CAIntermediates              string
	CARoots                      string
	CertChain                    string
	SigRef                       string
	TrustedRootPath              string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	IgnoreSCT                    bool
	SCTRef                       string
	Offline                      bool
	UseSignedTimestamps          bool
	IgnoreTlog                   bool
	HashAlgorithm                crypto.Hash
}

// nolint
func (c *VerifyBlobCmd) Exec(ctx context.Context, blobRef string) error {
	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
	}

	// Require a certificate/key OR a local bundle file that has the cert.
	if options.NOf(c.KeyRef, c.CertRef, c.Sk, c.BundlePath) == 0 {
		return fmt.Errorf("provide a key with --key or --sk, a certificate to verify against with --certificate, or a bundle with --bundle")
	}

	// Key, sk, and cert are mutually exclusive.
	if options.NOf(c.KeyRef, c.Sk, c.CertRef) > 1 {
		return &options.PubKeyParseError{}
	}

	var identities []cosign.Identity
	var err error
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	co := &cosign.CheckOpts{
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		UseSignedTimestamps:          c.TSACertChainPath != "" || c.UseSignedTimestamps,
		NewBundleFormat:              c.KeyOpts.NewBundleFormat && checkNewBundle(c.BundlePath),
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.CertRef, c.Sk, co)

	// User provides a key or certificate. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle or OCI annotation.
	var closeSV func()
	var cert *x509.Certificate
	co.SigVerifier, cert, closeSV, err = LoadVerifierFromKeyOrCert(ctx, c.KeyRef, c.Slot, c.CertRef, "", c.HashAlgorithm, c.Sk, true, co)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	err = SetTrustedMaterial(ctx, c.TrustedRootPath, c.CertChain, c.CARoots, c.CAIntermediates, c.TSACertChainPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	if err = CheckSigstoreBundleUnsupportedOptions(*c, vOfflineKey, co); err != nil {
		return err
	}

	if co.NewBundleFormat {
		bundle, err := sgbundle.LoadJSONFromPath(c.BundlePath)
		if err != nil {
			return err
		}

		var artifactPolicyOption sgverify.ArtifactPolicyOption
		blobBytes, err := payloadBytes(blobRef)
		if err != nil {
			alg, digest, payloadDigestError := payloadDigest(blobRef)
			if payloadDigestError != nil {
				return err
			}
			artifactPolicyOption = sgverify.WithArtifactDigest(alg, digest)
		} else {
			artifactPolicyOption = sgverify.WithArtifact(bytes.NewReader(blobBytes))
		}

		_, err = cosign.VerifyNewBundle(ctx, co, artifactPolicyOption, bundle)
		if err != nil {
			return err
		}

		ui.Infof(ctx, "Verified OK")
		return nil
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	if c.TrustedRootPath != "" {
		return fmt.Errorf("--trusted-root only supported with --new-bundle-format")
	}
	if c.RFC3161TimestampPath != "" && !co.UseSignedTimestamps {
		return fmt.Errorf("when specifying --rfc3161-timestamp-path, you must also specify --use-signed-timestamps or --timestamp-certificate-chain")
	} else if c.RFC3161TimestampPath == "" && co.UseSignedTimestamps {
		return fmt.Errorf("when specifying --use-signed-timestamps or --timestamp-certificate-chain, you must also specify --rfc3161-timestamp-path")
	}

	err = SetLegacyClientsAndKeys(ctx, c.IgnoreTlog, shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk), keylessVerification(c.KeyRef, c.Sk), c.RekorURL, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, co)
	if err != nil {
		return fmt.Errorf("setting up clients and keys: %w", err)
	}

	opts := make([]static.Option, 0)
	if c.BundlePath != "" {
		b, err := cosign.FetchLocalSignedPayloadFromPath(c.BundlePath)
		if err != nil {
			return err
		}
		// A certificate is required in the bundle unless we specified with
		//  --key, --sk, or --certificate.
		if b.Cert == "" && co.SigVerifier == nil && cert == nil {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
		// We have to condition on this because sign-blob may not output the signing
		// key to the bundle when there is no tlog upload.
		if b.Cert != "" {
			// b.Cert can either be a certificate or public key
			certBytes := []byte(b.Cert)
			if isb64(certBytes) {
				certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
			}
			bundleCert, err := loadCertFromPEM(certBytes)
			if err != nil {
				// check if cert is actually a public key
				co.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
				if err != nil {
					return fmt.Errorf("loading verifier from bundle: %w", err)
				}
			}
			// if a cert was passed in, make sure it matches the cert in the bundle
			if cert != nil && !cert.Equal(bundleCert) {
				return fmt.Errorf("the cert passed in does not match the cert in the provided bundle")
			}
			cert = bundleCert
		}
		opts = append(opts, static.WithBundle(b.Bundle))
	}
	if c.RFC3161TimestampPath != "" {
		var rfc3161Timestamp bundle.RFC3161Timestamp
		ts, err := blob.LoadFileOrURL(c.RFC3161TimestampPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(ts, &rfc3161Timestamp); err != nil {
			return err
		}
		opts = append(opts, static.WithRFC3161Timestamp(&rfc3161Timestamp))
	}
	// Set an SCT if provided via the CLI.
	if c.SCTRef != "" {
		sct, err := os.ReadFile(filepath.Clean(c.SCTRef))
		if err != nil {
			return fmt.Errorf("reading sct from file: %w", err)
		}
		co.SCT = sct
	}
	// Set a cert chain if provided.
	var chainPEM []byte
	switch {
	case c.CertChain != "":
		chain, err := loadCertChainFromFileOrURL(c.CertChain)
		if err != nil {
			return err
		}
		if chain == nil {
			return errors.New("expected certificate chain in --certificate-chain")
		}
		// Set the last one in the co.RootCerts. This is trusted, as its passed in
		// via the CLI.
		if co.RootCerts == nil {
			co.RootCerts = x509.NewCertPool()
		}
		co.RootCerts.AddCert(chain[len(chain)-1])
		// Use the whole as the cert chain in the signature object.
		// The last one is omitted because it is considered the "root".
		chainPEM, err = cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return err
		}
	case c.CARoots != "":
		// CA roots + possible intermediates are already loaded into co.RootCerts with the call to
		// loadCertsKeylessVerification above.
	}

	// Gather the cert for the signature and add the cert along with the
	// cert chain into the signature object.
	var certPEM []byte
	if cert != nil {
		certPEM, err = cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return err
		}
		opts = append(opts, static.WithCertChain(certPEM, chainPEM))
	}

	sig, err := base64signature(c.SigRef, c.BundlePath)
	if err != nil {
		return err
	}
	signature, err := static.NewSignature(blobBytes, sig, opts...)
	if err != nil {
		return err
	}
	if _, err = cosign.VerifyBlobSignature(ctx, signature, co); err != nil {
		return err
	}

	ui.Infof(ctx, "Verified OK")
	return nil
}

// base64signature returns the base64 encoded signature
func base64signature(sigRef, bundlePath string) (string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", err
			}
			targetSig = []byte(sigRef)
		}
	case bundlePath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
		if err != nil {
			return "", err
		}
		targetSig = []byte(b.Base64Signature)
	default:
		return "", fmt.Errorf("missing flag '--signature'")
	}

	if isb64(targetSig) {
		return string(targetSig), nil
	}
	return base64.StdEncoding.EncodeToString(targetSig), nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

func payloadDigest(blobRef string) (string, []byte, error) {
	hexAlg, hexDigest, ok := strings.Cut(blobRef, ":")
	if !ok {
		return "", nil, fmt.Errorf("invalid digest format")
	}
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		return "", nil, err
	}
	return hexAlg, digestBytes, nil
}
