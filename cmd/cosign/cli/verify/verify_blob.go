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
	CertRef                      string
	CertEmail                    string
	CertIdentity                 string
	CertOIDCIssuer               string
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
}

// nolint
func (c *VerifyBlobCmd) Exec(ctx context.Context, blobRef string) error {
	var cert *x509.Certificate
	var chain []*x509.Certificate
	opts := make([]static.Option, 0)

	// Require a certificate/key OR a local bundle file that has the cert.
	if options.NOf(c.KeyRef, c.CertRef, c.Sk, c.BundlePath) == 0 {
		return fmt.Errorf("please provide a cert to verify against via --certificate or a bundle via --bundle")
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	sig, err := base64signature(c.SigRef, c.BundlePath)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	co := &cosign.CheckOpts{
		CertEmail:                    c.CertEmail,
		CertIdentity:                 c.CertIdentity,
		CertOidcIssuer:               c.CertOIDCIssuer,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Offline:                      c.Offline,
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
		if c.CertChain != "" {
			// Verify certificate with chain
			chain, err = loadCertChainFromFileOrURL(c.CertChain)
			if err != nil {
				return err
			}
		}
		if c.SCTRef != "" {
			sct, err := os.ReadFile(filepath.Clean(c.SCTRef))
			if err != nil {
				return fmt.Errorf("reading sct from file: %w", err)
			}
			co.SCT = sct
		}
	}
	if c.BundlePath != "" {
		b, err := cosign.FetchLocalSignedPayloadFromPath(c.BundlePath)
		if err != nil {
			return err
		}
		if b.Cert == "" {
			return fmt.Errorf("bundle does not contain cert for verification, please provide public key")
		}
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
		} else {
			if c.CertChain != "" {
				// Load certificate chain
				chain, err = loadCertChainFromFileOrURL(c.CertChain)
				if err != nil {
					return err
				}
			}
		}
		opts = append(opts, static.WithBundle(b.Bundle))
	}

	// Gather the cert for the signature.
	var certPEM []byte
	if cert != nil {
		certPEM, err = cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return err
		}
	}
	var chainPEM []byte
	if chain != nil {
		// Set the last one in the co.RootCerts
		if co.RootCerts == nil {
			co.RootCerts = x509.NewCertPool()
		}
		co.RootCerts.AddCert(chain[len(chain)-1])
		// Use the rest as the cert chain.
		chainPEM, err = cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return err
		}
	}
	opts = append(opts, static.WithCertChain(certPEM, chainPEM))

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
func base64signature(sigRef string, bundlePath string) (string, error) {
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
