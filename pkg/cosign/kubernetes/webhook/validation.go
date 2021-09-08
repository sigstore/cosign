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
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
)

func valid(ctx context.Context, img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := validSignatures(ctx, img, k)
		if err != nil {
			logging.FromContext(ctx).Errorf("error validating signatures: %v", err)
			return false
		}
		if len(sps) > 0 {
			return true
		}
	}
	logging.FromContext(ctx).Debug("No valid signatures were found.")
	return false
}

func validSignatures(ctx context.Context, img string, key *ecdsa.PublicKey) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return nil, err
	}

	ecdsaVerifier, err := signature.LoadECDSAVerifier(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return cosign.Verify(ctx, ref, &cosign.CheckOpts{
		RootCerts:     fulcioroots.Get(),
		SigVerifier:   ecdsaVerifier,
		ClaimVerifier: cosign.SimpleClaimVerifier,
	})
}

func getKeys(ctx context.Context, cfg map[string][]byte) ([]*ecdsa.PublicKey, *apis.FieldError) {
	keys := []*ecdsa.PublicKey{}

	logging.FromContext(ctx).Debugf("Got public key: %v", cfg["cosign.pub"])

	pems := parsePems(cfg["cosign.pub"])
	for i, p := range pems {
		// TODO: (@dlorenc) check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, apis.ErrGeneric(fmt.Sprintf("malformed cosign.pub (pem: %d): %v", i, err), apis.CurrentField)
		}
		keys = append(keys, key.(*ecdsa.PublicKey))
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
