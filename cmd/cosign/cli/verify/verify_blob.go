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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci/static"
	sigs "github.com/sigstore/cosign/pkg/signature"

	ctypes "github.com/sigstore/cosign/pkg/types"
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
	CertChain                    string
	SigRef                       string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	IgnoreSCT                    bool
	SCTRef                       string
	Offline                      bool
	SkipTlogVerify               bool
}

// nolint
func (c *VerifyBlobCmd) Exec(ctx context.Context, blobRef string) error {
	var cert *x509.Certificate
	opts := make([]static.Option, 0)

	// Require a certificate/key OR a local bundle file that has the cert.
	if options.NOf(c.KeyRef, c.CertRef, c.Sk, c.BundlePath, c.RFC3161TimestampPath) == 0 {
		return fmt.Errorf("please provide a cert to verify against via --certificate or a bundle via --bundle or --rfc3161-timestamp-bundle")
	}

	// Key, sk, and cert are mutually exclusive.
	if options.NOf(c.KeyRef, c.Sk, c.CertRef) > 1 {
		return &options.KeyParseError{}
	}

	var identities []cosign.Identity
	var err error
	if c.KeyRef == "" {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	sig, err := base64signature(c.SigRef, c.BundlePath, c.RFC3161TimestampPath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
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
		SkipTlogVerify:               c.SkipTlogVerify,
	}
	if c.RFC3161TimestampPath != "" && c.KeyOpts.TSACertChainPath == "" {
		return fmt.Errorf("timestamp-cert-chain is required to validate a rfc3161 timestamp bundle")
	}
	if c.KeyOpts.TSACertChainPath != "" {
		_, err := os.Stat(c.KeyOpts.TSACertChainPath)
		if err != nil {
			return fmt.Errorf("unable to open timestamp certificate chain file '%s: %w", c.KeyOpts.TSACertChainPath, err)
		}
		// TODO: Add support for TUF certificates.
		pemBytes, err := os.ReadFile(filepath.Clean(c.KeyOpts.TSACertChainPath))
		if err != nil {
			return fmt.Errorf("error reading certification chain path file: %w", err)
		}
		// TODO: Update this logic once https://github.com/sigstore/timestamp-authority/issues/121 gets merged.
		// This relies on untrusted leaf certificate.
		tsaCertPool := x509.NewCertPool()
		ok := tsaCertPool.AppendCertsFromPEM(pemBytes)
		if !ok {
			return fmt.Errorf("error parsing response into Timestamp while appending certs from PEM")
		}
		co.TSACerts = tsaCertPool
	}

	if keylessVerification(c.KeyRef, c.Sk) {
		if c.RekorURL != "" {
			rekorClient, err := rekor.NewClient(c.RekorURL)
			if err != nil {
				return fmt.Errorf("creating Rekor client: %w", err)
			}
			co.RekorClient = rekorClient
		}
		// Use default TUF roots if a cert chain is not provided.
		if c.CertChain == "" {
			co.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return fmt.Errorf("getting Fulcio roots: %w", err)
			}
			co.IntermediateCerts, err = fulcio.GetIntermediates()
			if err != nil {
				return fmt.Errorf("getting Fulcio intermediates: %w", err)
			}
		}
	}

	// Keys are optional!
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
			cert, err = loadCertFromPEM(certBytes)
			if err != nil {
				// check if cert is actually a public key
				co.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
				if err != nil {
					return fmt.Errorf("loading verifier from bundle: %w", err)
				}
			}
		}
		opts = append(opts, static.WithBundle(b.Bundle))
	}
	if c.RFC3161TimestampPath != "" {
		b, err := cosign.FetchLocalSignedPayloadFromPath(c.RFC3161TimestampPath)
		if err != nil {
			return err
		}
		// Note: RFC3161 timestamp does not set the certificate.
		// We have to condition on this because sign-blob may not output the signing
		// key to the bundle when there is no tlog upload.
		if b.Cert != "" {
			// b.Cert can either be a certificate or public key
			certBytes := []byte(b.Cert)
			if isb64(certBytes) {
				certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
			}
			cert, err = loadCertFromPEM(certBytes)
			if err != nil {
				// check if cert is actually a public key
				co.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
				if err != nil {
					return fmt.Errorf("loading verifier from rfc3161 timestamp bundle: %w", err)
				}
			}
		}
		opts = append(opts, static.WithRFC3161Timestamp(b.RFC3161Timestamp))
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

	// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
	// TODO: This verifier only supports verification of a single signer/signature on
	// the envelope. Either have the verifier validate that only one signature exists,
	// or use a multi-signature verifier.
	if isIntotoDSSE(blobBytes) {
		// co.SigVerifier = dsse.WrapVerifier(co.SigVerifier)
		signature, err := static.NewAttestation(blobBytes, opts...)
		if err != nil {
			return err
		}
		// We have no artifact the attestation is tied to, so we can't do any claim
		// verification.
		// TODO: Add an option to support this to populate the v1.Hash for a claim.
		if _, err = cosign.VerifyBlobAttestation(ctx, signature, co); err != nil {
			return err
		}
	} else {
		signature, err := static.NewSignature(blobBytes, sig, opts...)
		if err != nil {
			return err
		}
		if _, err = cosign.VerifyBlobSignature(ctx, signature, co); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

// base64signature returns the base64 encoded signature
func base64signature(sigRef string, bundlePath, rfc3161TimestampPath string) (string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
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
	case rfc3161TimestampPath != "":
		b, err := cosign.FetchLocalSignedPayloadFromPath(rfc3161TimestampPath)
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

// isIntotoDSSE checks whether a payload is a Dead Simple Signing Envelope with the In-Toto format.
func isIntotoDSSE(blobBytes []byte) bool {
	DSSEenvelope := ssldsse.Envelope{}
	if err := json.Unmarshal(blobBytes, &DSSEenvelope); err != nil {
		return false
	}
	if DSSEenvelope.PayloadType != ctypes.IntotoPayloadType {
		return false
	}

	return true
}
