// Copyright 2022 The Sigstore Authors.
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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-openapi/runtime"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	ctypes "github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

type blobSignature struct {
	payload []byte
	b64sig  string
	bundle  *bundle.RekorBundle
	v1.Layer
}

func newBundleSignature(blobBytes []byte, b64sig string, bundle *bundle.RekorBundle) (*blobSignature, error) {
	if blobBytes == nil {
		return nil, errors.New("blobBytes must be non nil")
	}
	if b64sig == "" {
		return nil, errors.New("b64sig must be non empty string")
	}
	return &blobSignature{
		payload: blobBytes,
		b64sig:  b64sig,
		bundle:  bundle,
	}, nil
}

func (s *blobSignature) Annotations() (map[string]string, error) {
	return nil, nil
}

func (s *blobSignature) Payload() ([]byte, error) {
	return s.payload, nil
}

func (s *blobSignature) Base64Signature() (string, error) {
	return s.b64sig, nil
}

func (s *blobSignature) Cert() (*x509.Certificate, error) {
	return nil, errors.New("no cert in blobSignature")
}

func (s *blobSignature) Chain() ([]*x509.Certificate, error) {
	return nil, errors.New("no cert chain in blobSignature")
}

func (s *blobSignature) Bundle() (*bundle.RekorBundle, error) {
	return s.bundle, nil
}

// VerifyBlobSignature verifies a signature
func VerifyBlobSignature(ctx context.Context, blobBytes []byte, b64sig string, bundle *bundle.RekorBundle, co *CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	sig, err := newBundleSignature(blobBytes, b64sig, bundle)
	if err != nil {
		return checkedSignatures, bundleVerified, errors.Wrap(err, "failed to create bundle signature")
	}

	verifiers := []signature.Verifier{}
	if co.SigVerifier != nil {
		verifiers = append(verifiers, co.SigVerifier)
	} else {
		uuids, err := FindTLogEntriesByPayload(ctx, co.RekorClient, blobBytes)
		if err != nil {
			return checkedSignatures, bundleVerified, errors.Wrap(err, "failed to get tlog entries by payload")
		}
		if len(uuids) == 0 {
			return checkedSignatures, bundleVerified, errors.New("could not find a tlog entry for provided blob")
		}
		for _, u := range uuids {
			tlogEntry, err := GetTlogEntry(ctx, co.RekorClient, u)
			if err != nil {
				continue
			}
			certs, err := extractCerts(tlogEntry)
			if err != nil {
				continue
			}
			cert := certs[0]
			verifier, err := ValidateAndUnpackCert(cert, co)
			if err != nil {
				continue
			}
			// Use the DSSE verifier if the payload is a DSSE with the In-Toto format.
			if isIntotoDSSE(blobBytes) {
				verifier = dsse.WrapVerifier(verifier)
			}
			verifiers = append(verifiers, verifier)
		}
	}

	var validSigExists bool
	for _, verifier := range verifiers {
		if err := verifyOCISignature(ctx, verifier, sig); err != nil {
			continue
		}
		bundleVerified = true
		validSigExists = true
		break
	}
	if !validSigExists {
		fmt.Fprintln(os.Stderr, `WARNING: No valid entries were found in rekor to verify this blob.
Transparency log support for blobs is experimental, and occasionally an entry isn't found even if one exists.
We recommend requesting the certificate/signature from the original signer of this blob and manually verifying with cosign verify-blob --cert [cert] --signature [signature].`)
		return checkedSignatures, bundleVerified, fmt.Errorf("could not find a valid tlog entry for provided blob, found %d invalid entries", len(verifiers))
	}

	if validSigExists {
		fmt.Fprintln(os.Stderr, "Verified OK")
		checkedSignatures = append(checkedSignatures, sig)
	}

	if !validSigExists && co.RekorClient != nil {
		if co.SigVerifier != nil {
			pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
			if err != nil {
				return checkedSignatures, bundleVerified, errors.Wrap(err, "failed to get pubkey")
			}
			return checkedSignatures, bundleVerified, tlogValidatePublicKey(ctx, co.RekorClient, pub, sig)
		}

		return checkedSignatures, bundleVerified, tlogValidateCertificate(ctx, co.RekorClient, sig)
	}

	return checkedSignatures, bundleVerified, nil
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
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
