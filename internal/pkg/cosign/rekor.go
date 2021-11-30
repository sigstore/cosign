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

package cosign

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	cosignv1 "github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
	rekPkgClient "github.com/sigstore/rekor/pkg/client"
	rekGenClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func bundle(entry *models.LogEntryAnon) *oci.Bundle {
	if entry.Verification == nil {
		return nil
	}
	return &oci.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Payload: oci.BundlePayload{
			Body:           entry.Body,
			IntegratedTime: *entry.IntegratedTime,
			LogIndex:       *entry.LogIndex,
			LogID:          *entry.LogID,
		},
	}
}

type tlogUploadFn func(*rekGenClient.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(rekorBytes []byte, rekorURL string, upload tlogUploadFn) (*oci.Bundle, error) {
	rekorClient, err := rekPkgClient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return bundle(entry), nil
}

// RekorSignerWrapper calls a wrapped, inner signer then uploads either the Cert or Pub(licKey) of the results to Rekor, then adds the resulting `Bundle`
type RekorSignerWrapper struct {
	Inner Signer

	RekorURL string
}

// Sign implements `Signer`
func (rs *RekorSignerWrapper) Sign(ctx context.Context, payload io.Reader) (oci.Signature, crypto.PublicKey, error) {
	sig, pub, err := rs.Inner.Sign(ctx, payload)
	if err != nil {
		return nil, nil, err
	}

	payloadBytes, err := sig.Payload()
	if err != nil {
		return nil, nil, err
	}
	b64Sig, err := sig.Base64Signature()
	if err != nil {
		return nil, nil, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, nil, err
	}

	// Upload the cert or the public key, depending on what we have
	cert, err := sig.Cert()
	if err != nil {
		return nil, nil, err
	}

	var rekorBytes []byte
	if cert != nil {
		rekorBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
	} else {
		rekorBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
	}
	if err != nil {
		return nil, nil, err
	}

	bundle, err := uploadToTlog(rekorBytes, rs.RekorURL, func(r *rekGenClient.Rekor, b []byte) (*models.LogEntryAnon, error) {
		return cosignv1.TLogUpload(ctx, r, sigBytes, payloadBytes, b)
	})
	if err != nil {
		return nil, nil, err
	}

	opts := []static.Option{static.WithBundle(bundle)}

	// Copy over the other attributes:

	if cert != nil {
		chain, err := sig.Chain()
		if err != nil {
			return nil, nil, err
		}
		chainBytes, err := cryptoutils.MarshalCertificatesToPEM(chain)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, static.WithCertChain(rekorBytes, chainBytes))
	}
	if annotations, err := sig.Annotations(); err != nil {
		return nil, nil, err
	} else if len(annotations) > 0 {
		opts = append(opts, static.WithAnnotations(annotations))
	}
	if mt, err := sig.MediaType(); err != nil {
		return nil, nil, err
	} else if mt != "" {
		opts = append(opts, static.WithLayerMediaType(mt))
	}

	newSig, err := static.NewSignature(payloadBytes, b64Sig, opts...)
	if err != nil {
		return nil, nil, err
	}

	return newSig, pub, nil
}
