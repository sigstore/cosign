//
// Copyright 2022 the Sigstore Authors.
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	internal "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	payloadsize "github.com/sigstore/cosign/v2/internal/pkg/cosign/payload/size"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v2/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/policy"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// VerifyBlobAttestationCommand verifies an attestation on a supplied blob
// nolint
type VerifyBlobAttestationCommand struct {
	options.KeyOpts
	options.CertVerifyOptions

	CertRef         string
	CertChain       string
	CAIntermediates string
	CARoots         string
	TrustedRootPath string

	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string

	IgnoreSCT  bool
	SCTRef     string
	Offline    bool
	IgnoreTlog bool

	CheckClaims   bool
	PredicateType string
	// TODO: Add policies

	SignaturePath       string // Path to the signature
	UseSignedTimestamps bool

	Digest    string
	DigestAlg string
}

// Exec runs the verification command
func (c *VerifyBlobAttestationCommand) Exec(ctx context.Context, artifactPath string) (err error) {
	if options.NOf(c.SignaturePath, c.BundlePath) == 0 {
		return fmt.Errorf("please specify path to the DSSE envelope signature via --signature or --bundle")
	}

	// Require a certificate/key OR a local bundle file that has the cert.
	if options.NOf(c.KeyRef, c.CertRef, c.Sk, c.BundlePath) == 0 {
		return fmt.Errorf("provide a key with --key or --sk, a certificate to verify against with --certificate, or a bundle with --bundle")
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	var identities []cosign.Identity
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	co := &cosign.CheckOpts{
		Identities:                   identities,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		UseSignedTimestamps:          c.TSACertChainPath != "" || c.UseSignedTimestamps,
		NewBundleFormat:              c.NewBundleFormat || checkNewBundle(c.BundlePath),
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
	case c.CARoots != "":
		// CA roots + possible intermediates are already loaded into co.RootCerts with the call to
		// loadCertsKeylessVerification above.
	}

	var h v1.Hash
	var digest []byte
	if c.CheckClaims {
		if artifactPath != "" {
			if c.Digest != "" && c.DigestAlg != "" {
				ui.Warnf(ctx, "Ignoring provided digest and digestAlg in favor of provided blob")
			}
			// Get the actual digest of the blob
			var payload internal.HashReader
			f, err := os.Open(filepath.Clean(artifactPath))
			if err != nil {
				return err
			}
			defer f.Close()
			fileInfo, err := f.Stat()
			if err != nil {
				return err
			}
			err = payloadsize.CheckSize(uint64(fileInfo.Size()))
			if err != nil {
				return err
			}

			payload = internal.NewHashReader(f, sha256.New())
			if _, err := io.ReadAll(&payload); err != nil {
				return err
			}
			digest = payload.Sum(nil)
			h = v1.Hash{
				Hex:       hex.EncodeToString(digest),
				Algorithm: "sha256",
			}
		} else if c.Digest != "" && c.DigestAlg != "" {
			digest, err = hex.DecodeString(c.Digest)
			if err != nil {
				return fmt.Errorf("unable to decode provided digest: %w", err)
			}
			h = v1.Hash{
				Hex:       c.Digest,
				Algorithm: c.DigestAlg,
			}
		}
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	if c.TrustedRootPath != "" {
		co.TrustedMaterial, err = root.NewTrustedRootFromPath(c.TrustedRootPath)
		if err != nil {
			return fmt.Errorf("loading trusted root: %w", err)
		}
	} else if options.NOf(c.CertChain, c.CARoots, c.CAIntermediates, c.TSACertChainPath) == 0 &&
		env.Getenv(env.VariableSigstoreCTLogPublicKeyFile) == "" &&
		env.Getenv(env.VariableSigstoreRootFile) == "" &&
		env.Getenv(env.VariableSigstoreRekorPublicKey) == "" &&
		env.Getenv(env.VariableSigstoreTSACertificateFile) == "" {
		co.TrustedMaterial, err = cosign.TrustedRoot()
		if err != nil {
			ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF repository. Continuing with individual targets. Error from TUF: %v", err)
		}
	}

	if co.NewBundleFormat {
		if options.NOf(c.RFC3161TimestampPath, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, c.CertRef, c.SCTRef) > 0 {
			return fmt.Errorf("when using --new-bundle-format, please supply signed content with --bundle and verification content with --trusted-root")
		}

		if co.TrustedMaterial == nil {
			return fmt.Errorf("trusted root is required when using new bundle format")
		}

		bundle, err := sgbundle.LoadJSONFromPath(c.BundlePath)
		if err != nil {
			return err
		}

		_, err = cosign.VerifyNewBundle(ctx, co, sgverify.WithArtifactDigest(h.Algorithm, digest), bundle)
		if err != nil {
			return err
		}

		ui.Infof(ctx, "Verified OK")
		return nil
	}

	if c.TrustedRootPath != "" {
		return fmt.Errorf("--trusted-root only supported with --new-bundle-format")
	}
	if c.RFC3161TimestampPath != "" && !co.UseSignedTimestamps {
		return fmt.Errorf("when specifying --rfc3161-timestamp-path, you must also specify --use-signed-timestamps or --timestamp-certificate-chain")
	} else if c.RFC3161TimestampPath == "" && co.UseSignedTimestamps {
		return fmt.Errorf("when specifying --use-signed-timestamps or --timestamp-certificate-chain, you must also specify --rfc3161-timestamp-path")
	}
	if co.UseSignedTimestamps && co.TrustedMaterial == nil {
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
		if co.TrustedMaterial == nil {
			// This performs an online fetch of the Rekor public keys, but this is needed
			// for verifying tlog entries (both online and offline).
			co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
			if err != nil {
				return fmt.Errorf("getting Rekor public keys: %w", err)
			}
		}
	}
	if co.TrustedMaterial == nil && keylessVerification(c.KeyRef, c.Sk) {
		if err := loadCertsKeylessVerification(c.CertChain, c.CARoots, c.CAIntermediates, co); err != nil {
			return err
		}
	}

	// Ignore Signed Certificate Timestamp if the flag is set or a key is provided
	if co.TrustedMaterial == nil && shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk) {
		co.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return fmt.Errorf("getting ctlog public keys: %w", err)
		}
	}

	var encodedSig []byte
	if c.SignaturePath != "" {
		encodedSig, err = os.ReadFile(filepath.Clean(c.SignaturePath))
		if err != nil {
			return fmt.Errorf("reading %s: %w", c.SignaturePath, err)
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

		encodedSig, err = base64.StdEncoding.DecodeString(b.Base64Signature)
		if err != nil {
			return fmt.Errorf("decoding signature: %w", err)
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
	if c.CertChain != "" {
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

	signature, err := static.NewAttestation(encodedSig, opts...)
	if err != nil {
		return err
	}

	// TODO: This verifier only supports verification of a single signer/signature on
	// the envelope. Either have the verifier validate that only one signature exists,
	// or use a multi-signature verifier.
	if _, err = cosign.VerifyBlobAttestation(ctx, signature, h, co); err != nil {
		return err
	}

	// This checks the predicate type -- if no error is returned and no payload is, then
	// the attestation is not of the given predicate type.
	if b, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, signature); b == nil && err == nil {
		return fmt.Errorf("invalid predicate type, expected %s got %s", c.PredicateType, gotPredicateType)
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}
