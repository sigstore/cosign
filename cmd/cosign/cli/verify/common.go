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
