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

package webhook

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature"
)

func valid(ctx context.Context, ref name.Reference, keys []*ecdsa.PublicKey, opts ...ociremote.Option) ([]oci.Signature, error) {
	if len(keys) == 0 {
		// If there are no keys, then verify against the fulcio root.
		sps, err := validSignaturesWithFulcio(ctx, ref, fulcioroots.Get(), nil /* rekor */, opts...)
		if err != nil {
			return nil, err
		}
		if len(sps) > 0 {
			return sps, nil
		}
		return nil, errors.New("no valid signatures were found")
	}
	// We return nil if ANY key matches
	var lastErr error
	for _, k := range keys {
		verifier, err := signature.LoadECDSAVerifier(k, crypto.SHA256)
		if err != nil {
			logging.FromContext(ctx).Errorf("error creating verifier: %v", err)
			lastErr = err
			continue
		}

		sps, err := validSignatures(ctx, ref, verifier, opts...)
		if err != nil {
			logging.FromContext(ctx).Errorf("error validating signatures: %v", err)
			lastErr = err
			continue
		}
		if len(sps) > 0 {
			return sps, nil
		}
	}
	logging.FromContext(ctx).Debug("No valid signatures were found.")
	return nil, lastErr
}

// For testing
var cosignVerifySignatures = cosign.VerifyImageSignatures

func validSignatures(ctx context.Context, ref name.Reference, verifier signature.Verifier, opts ...ociremote.Option) ([]oci.Signature, error) {
	sigs, _, err := cosignVerifySignatures(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		SigVerifier:        verifier,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
	})
	return sigs, err
}

// validSignaturesWithFulcio expects a Fulcio Cert to verify against. An
// optional rekorClient can also be given, if nil passed, default is assumed.
func validSignaturesWithFulcio(ctx context.Context, ref name.Reference, fulcioRoots *x509.CertPool, rekorClient *client.Rekor, opts ...ociremote.Option) ([]oci.Signature, error) {
	sigs, _, err := cosignVerifySignatures(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		RootCerts:          fulcioRoots,
		RekorClient:        rekorClient,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
	})
	return sigs, err
}

func getKeys(ctx context.Context, cfg map[string][]byte) ([]*ecdsa.PublicKey, *apis.FieldError) {
	keys := []*ecdsa.PublicKey{}
	errs := []error{}

	logging.FromContext(ctx).Debugf("Got public key: %v", cfg["cosign.pub"])

	pems := parsePems(cfg["cosign.pub"])
	for _, p := range pems {
		// TODO: (@dlorenc) check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			errs = append(errs, err)
		} else {
			keys = append(keys, key.(*ecdsa.PublicKey))
		}
	}
	if keys == nil {
		return nil, apis.ErrGeneric(fmt.Sprintf("malformed cosign.pub: %v", errs), apis.CurrentField)
	}
	return keys, nil
}

func parseAuthorityKeys(ctx context.Context, pubKey string) ([]*ecdsa.PublicKey, *apis.FieldError) {
	keys := []*ecdsa.PublicKey{}
	errs := []error{}

	logging.FromContext(ctx).Debugf("Got public key: %v", pubKey)

	pems := parsePems([]byte(pubKey))
	for _, p := range pems {
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			errs = append(errs, err)
		} else {
			keys = append(keys, key.(*ecdsa.PublicKey))
		}
	}
	if len(keys) == 0 {
		return nil, apis.ErrGeneric(fmt.Sprintf("malformed authority key data: %v", errs), apis.CurrentField)
	}
	return keys, nil
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
