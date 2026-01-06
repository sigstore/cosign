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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	payloadsize "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload/size"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/policy"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
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

	Digest        string
	DigestAlg     string
	HashAlgorithm crypto.Hash
}

// Exec runs the verification command
func (c *VerifyBlobAttestationCommand) Exec(ctx context.Context, artifactPath string) (err error) {
	if options.NOf(c.SignaturePath, c.BundlePath) == 0 {
		return fmt.Errorf("please specify path to the DSSE envelope signature via --signature or --bundle")
	}

	// always default to sha256 if the algorithm hasn't been explicitly set
	if c.HashAlgorithm == 0 {
		c.HashAlgorithm = crypto.SHA256
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
		NewBundleFormat:              c.NewBundleFormat && checkNewBundle(c.BundlePath),
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

			payload = internal.NewHashReader(f, crypto.SHA256)
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

		var policyOpt sgverify.ArtifactPolicyOption
		if c.CheckClaims {
			policyOpt = sgverify.WithArtifactDigest(h.Algorithm, digest)
		} else {
			policyOpt = sgverify.WithoutArtifactUnsafe()
		}

		_, err = cosign.VerifyNewBundle(ctx, co, policyOpt, bundle)
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

	err = SetLegacyClientsAndKeys(ctx, c.IgnoreTlog, shouldVerifySCT(c.IgnoreSCT, c.KeyRef, c.Sk), keylessVerification(c.KeyRef, c.Sk), c.RekorURL, c.TSACertChainPath, c.CertChain, c.CARoots, c.CAIntermediates, co)
	if err != nil {
		return fmt.Errorf("setting up clients and keys: %w", err)
	}

	var encodedSig []byte
	if c.SignaturePath != "" {
		encodedSig, err = os.ReadFile(filepath.Clean(c.SignaturePath))
		if err != nil {
			return fmt.Errorf("reading %s: %w", c.SignaturePath, err)
		}
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
