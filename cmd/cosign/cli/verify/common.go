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
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"reflect"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	csignature "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
)

// CheckSigstoreBundleUnsupportedOptions checks for incompatible settings on any Verify* command struct when NewBundleFormat is used.
func CheckSigstoreBundleUnsupportedOptions(cmd any, co *cosign.CheckOpts) error {
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
	if co.TrustedMaterial == nil {
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
// It may perform an online fetch of keys, so using trusted root instead of these TUF v1 methos is recommended.
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
