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

package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-openapi/swag"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign/kms"
	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const pubKeyPemType = "PUBLIC KEY"

type PublicKey interface {
	signature.Verifier
	signature.PublicKeyProvider
}

func LoadPublicKey(ctx context.Context, keyRef string) (PublicKey, error) {
	// The key could be plaintext or in a file.
	// First check if the file exists.
	var pubBytes []byte

	if kmsKey, err := kms.Get(ctx, keyRef); err == nil {
		// KMS specified
		return kmsKey, nil
	}

	// PEM encoded file.
	b, err := ioutil.ReadFile(filepath.Clean(keyRef))
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}
	if p.Type != pubKeyPemType {
		return nil, fmt.Errorf("not public: %q", p.Type)
	}
	pubBytes = p.Bytes

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	return signature.ECDSAVerifier{Key: ed, HashAlg: crypto.SHA256}, nil
}

func getTlogEntry(rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		return &e, nil
	}
	return nil, errors.New("empty response")
}

func FindTlogEntry(rekorClient *client.Rekor, b64Sig string, payload, pubKey []byte) (string, error) {
	searchParams := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return "", errors.Wrap(err, "decoding base64 signature")
	}
	re := rekorEntry(payload, signature, pubKey)
	entry := &models.Rekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.RekordObj,
	}

	searchLogQuery.SetEntries([]models.ProposedEntry{entry})

	searchParams.SetEntry(&searchLogQuery)
	resp, err := rekorClient.Entries.SearchLogQuery(searchParams)
	if err != nil {
		return "", errors.Wrap(err, "searching log query")
	}
	if len(resp.Payload) == 0 {
		return "", errors.New("signature not found in transparency log")
	} else if len(resp.Payload) > 1 {
		return "", errors.New("multiple entries returned; this should not happen")
	}
	logEntry := resp.Payload[0]
	if len(logEntry) != 1 {
		return "", errors.New("UUID value can not be extracted")
	}

	params := entries.NewGetLogEntryByUUIDParams()
	for k := range logEntry {
		params.EntryUUID = k
	}
	lep, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return "", err
	}

	if len(lep.Payload) != 1 {
		return "", errors.New("UUID value can not be extracted")
	}
	e := lep.Payload[params.EntryUUID]

	hashes := [][]byte{}
	for _, h := range e.InclusionProof.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*e.InclusionProof.RootHash)
	leafHash, _ := hex.DecodeString(params.EntryUUID)

	v := logverifier.New(hasher.DefaultHasher)
	if err := v.VerifyInclusionProof(*e.InclusionProof.LogIndex, *e.InclusionProof.TreeSize, hashes, rootHash, leafHash); err != nil {
		return "", errors.Wrap(err, "verifying inclusion proof")
	}
	return params.EntryUUID, nil
}

// There are only payloads. Some have certs, some don't.
type CheckOpts struct {
	Annotations map[string]interface{}
	Claims      bool
	Tlog        bool
	PubKey      PublicKey
	Roots       *x509.CertPool
}

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func Verify(ctx context.Context, ref name.Reference, co CheckOpts) ([]SignedPayload, error) {
	// Enforce this up front.
	if co.Roots == nil && co.PubKey == nil {
		return nil, errors.New("one of public key or cert roots is required")
	}
	// TODO: Figure out if we'll need a client before creating one.
	rekorClient, err := app.GetRekorClient(TlogServer())
	if err != nil {
		return nil, err
	}

	// These are all the signatures attached to our image that we know how to parse.
	allSignatures, desc, err := FetchSignatures(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "fetching signatures")
	}

	validationErrs := []string{}
	checkedSignatures := []SignedPayload{}
	for _, sp := range allSignatures {
		switch {
		// We have a public key to check against.
		case co.PubKey != nil:
			if err := sp.VerifyKey(ctx, co.PubKey); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		// If we don't have a public key to check against, we can try a root cert.
		case co.Roots != nil:
			// There might be signatures with a public key instead of a cert, though
			if sp.Cert == nil {
				validationErrs = append(validationErrs, "no certificate found on signature")
				continue
			}
			pub := &signature.ECDSAVerifier{Key: sp.Cert.PublicKey.(*ecdsa.PublicKey), HashAlg: crypto.SHA256}
			// Now verify the signature, then the cert.
			if err := sp.VerifyKey(ctx, pub); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if err := sp.TrustedCert(co.Roots); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		}

		// We can't check annotations without claims, both require unmarshalling the payload.
		if co.Claims {
			ss := &payload.SimpleContainerImage{}
			if err := json.Unmarshal(sp.Payload, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			if err := sp.VerifyClaims(desc, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			if co.Annotations != nil {
				if !correctAnnotations(co.Annotations, ss.Optional) {
					validationErrs = append(validationErrs, "missing or incorrect annotation")
					continue
				}
			}
		}

		if co.Tlog {
			// Get the right public key to use (key or cert)
			var pemBytes []byte
			if co.PubKey != nil {
				pemBytes, err = PublicKeyPem(ctx, co.PubKey)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			} else {
				pemBytes = CertToPem(sp.Cert)
			}
			// Find the uuid then the entry.
			uuid, err := sp.VerifyTlog(rekorClient, pemBytes)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			// if we have a cert, we should check expiry
			if sp.Cert != nil {
				e, err := getTlogEntry(rekorClient, uuid)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
				// Expiry check is only enabled with Tlog support
				if err := checkExpiry(sp.Cert, time.Unix(e.IntegratedTime, 0)); err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			}
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sp)
	}
	if len(checkedSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, nil
}
func checkExpiry(cert *x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return fmt.Errorf("certificate expired before signatures were entered in log: %s is before %s",
			ft(cert.NotAfter), ft(it))
	}
	if cert.NotBefore.After(it) {
		return fmt.Errorf("certificate was issued after signatures were entered in log: %s is after %s",
			ft(cert.NotAfter), ft(it))
	}
	return nil
}

func (sp *SignedPayload) VerifyKey(ctx context.Context, pubKey PublicKey) error {
	signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
	if err != nil {
		return err
	}
	return pubKey.Verify(ctx, sp.Payload, signature)
}

func (sp *SignedPayload) VerifyClaims(d *v1.Descriptor, ss *payload.SimpleContainerImage) error {
	foundDgst := ss.Critical.Image.DockerManifestDigest
	if foundDgst != d.Digest.String() {
		return fmt.Errorf("invalid or missing digest in claim: %s", foundDgst)
	}
	return nil
}

func (sp *SignedPayload) VerifyTlog(rc *client.Rekor, publicKeyPem []byte) (string, error) {
	return FindTlogEntry(rc, sp.Base64Signature, sp.Payload, publicKeyPem)
}

func (sp *SignedPayload) TrustedCert(roots *x509.CertPool) error {
	return TrustedCert(sp.Cert, roots)
}

func TrustedCert(cert *x509.Certificate, roots *x509.CertPool) error {
	if _, err := cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime: cert.NotBefore,
		Roots:       roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageDigitalSignature),
			x509.ExtKeyUsageCodeSigning,
		},
	}); err != nil {
		return err
	}
	return nil
}

func correctAnnotations(wanted, have map[string]interface{}) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
