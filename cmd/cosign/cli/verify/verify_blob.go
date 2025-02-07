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

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
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
}

// nolint
func (c *VerifyBlobCmd) Exec(ctx context.Context, blobRef string) error {
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
		NewBundleFormat:              c.KeyOpts.NewBundleFormat || checkNewBundle(c.BundlePath),
	}

	// Keys are optional!
	var cert *x509.Certificate
	opts := make([]static.Option, 0)
	switch {
	case c.KeyRef != "":
		co.SigVerifier, err = sigs.PublicKeyFromKeyRef(ctx, c.KeyRef)
		if err != nil {
			return fmt.Errorf("loading public key: %w", err)
		}
		pkcs11Key, ok := co.SigVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case c.Sk:
		sk, err := pivkey.GetKeyWithSlot(c.Slot)
		if err != nil {
			return fmt.Errorf("opening piv token: %w", err)
		}
		defer sk.Close()
		co.SigVerifier, err = sk.Verifier()
		if err != nil {
			return fmt.Errorf("loading public key from token: %w", err)
		}
	case c.CertRef != "":
		cert, err = loadCertFromFileOrURL(c.CertRef)
		if err != nil {
			return err
		}
	}

	if co.NewBundleFormat {
		if options.NOf(c.RFC3161TimestampPath, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, c.CertRef, c.SigRef, c.SCTRef) > 0 {
			return fmt.Errorf("when using --new-bundle-format, please supply signed content with --bundle and verification content with --trusted-root")
		}

		if co.TrustedMaterial == nil {
			co.TrustedMaterial, err = loadTrustedRoot(ctx, c.TrustedRootPath)
			if err != nil {
				return err
			}
		}

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
	if co.UseSignedTimestamps {
		tsaCertificates, err := cosign.GetTSACerts(ctx, c.TSACertChainPath, cosign.GetTufTargets)
		if err != nil {
			return fmt.Errorf("unable to load TSA certificates: %w", err)
		}
		co.TSACertificate = tsaCertificates.LeafCert
		co.TSARootCertificates = tsaCertificates.RootCert
		co.TSAIntermediateCertificates = tsaCertificates.IntermediateCerts
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
		if err := loadCertsKeylessVerification(c.CertChain, c.CARoots, c.CAIntermediates, co); err != nil {
			return err
		}
	}
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

	// Ignore Signed Certificate Timestamp if the flag is set or a key is provided
	if shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk) {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
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

func loadTrustedRoot(_ context.Context, trustedRootPath string) (*root.TrustedRoot, error) {
	if trustedRootPath != "" {
		return root.NewTrustedRootFromPath(trustedRootPath)
	}
	// Assume we're using public good instance; fetch via TUF
	// TODO: allow custom TUF settings
	return root.FetchTrustedRoot()
}
