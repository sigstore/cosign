/*
Copyright The Sigstore Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cosign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/go-openapi/swag"
	"github.com/google/go-containerregistry/pkg/name"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/rekor/cmd/cli/app"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const pubKeyPemType = "PUBLIC KEY"

func LoadPublicKey(keyRef string) (*ecdsa.PublicKey, error) {
	// The key could be plaintext or in a file.
	// First check if the file exists.
	var pubBytes []byte
	if _, err := os.Stat(keyRef); os.IsNotExist(err) {
		pubBytes, err = base64.StdEncoding.DecodeString(keyRef)
		if err != nil {
			return nil, err
		}
	} else {
		// PEM encoded file.
		b, err := ioutil.ReadFile(keyRef)
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
	}

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	return ed, nil
}

func marshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty cert")
	}
	pubKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey,
	})
	return pubBytes, nil
}

func VerifySignature(pubkey *ecdsa.PublicKey, base64sig string, payload []byte) error {
	signature, err := base64.StdEncoding.DecodeString(base64sig)
	if err != nil {
		return err
	}

	h := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pubkey, h[:], signature) {
		return errors.New("unable to verify signature")
	}

	return nil
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

func findTlogEntry(rekorClient *client.Rekor, b64Sig string, payload, pubKey []byte) (string, error) {
	params := entries.NewGetLogEntryProofParams()
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

	entries := []models.ProposedEntry{entry}
	searchLogQuery.SetEntries(entries)

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

	for k := range logEntry {
		params.EntryUUID = k
	}
	lep, err := rekorClient.Entries.GetLogEntryProof(params)
	if err != nil {
		return "", err
	}

	hashes := [][]byte{}
	for _, h := range lep.Payload.Hashes {
		hb, _ := hex.DecodeString(h)
		hashes = append(hashes, hb)
	}

	rootHash, _ := hex.DecodeString(*lep.Payload.RootHash)
	leafHash, _ := hex.DecodeString(params.EntryUUID)

	v := logverifier.New(hasher.DefaultHasher)
	if err := v.VerifyInclusionProof(*lep.Payload.LogIndex, *lep.Payload.TreeSize, hashes, rootHash, leafHash); err != nil {
		return "", errors.Wrap(err, "verifying inclusion proof")
	}
	return params.EntryUUID, nil
}

// There are only payloads. Some have certs, some don't.
type CheckOpts struct {
	Annotations map[string]string
	Claims      bool
	Tlog        bool
	PubKey      *ecdsa.PublicKey
	Roots       *x509.CertPool
}

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func Verify(ref name.Reference, co CheckOpts) ([]SignedPayload, error) {
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
	allSignatures, desc, err := FetchSignatures(ref)
	if err != nil {
		return nil, err
	}

	validationErrs := []string{}
	checkedSignatures := []SignedPayload{}
	for _, sp := range allSignatures {
		// It's possible to have both a public key and certificates, but we'll make them mutually exclusive.
		if co.PubKey != nil {
			if err := sp.VerifyKey(co.PubKey); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		} else { // We must have roots since we don't have a public key
			// Check the signature first then the cert itself
			if err := sp.VerifyKey(sp.Cert.PublicKey.(*ecdsa.PublicKey)); err != nil {
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
			ss := &SimpleSigning{}
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
			var pk interface{}
			if co.PubKey != nil {
				pk = co.PubKey
			} else {
				pk = sp.Cert.PublicKey
			}
			pub, err := marshalPublicKey(pk.(*ecdsa.PublicKey))
			if err != nil {
				validationErrs = append(validationErrs, "missing or incorrect annotation")
				continue
			}

			// Find the uuid then the entry.
			uuid, err := sp.VerifyTlog(rekorClient, pub)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			// if we have a cert, we should check expirt
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

func (sp *SignedPayload) VerifyKey(pubKey *ecdsa.PublicKey) error {
	signature, err := base64.StdEncoding.DecodeString(sp.Base64Signature)
	if err != nil {
		return err
	}

	h := sha256.Sum256(sp.Payload)
	if !ecdsa.VerifyASN1(pubKey, h[:], signature) {
		return errors.New("unable to verify signature")
	}

	return nil
}

func (sp *SignedPayload) VerifyClaims(d *v1.Descriptor, ss *SimpleSigning) error {
	foundDgst := ss.Critical.Image.DockerManifestDigest
	if foundDgst != d.Digest.String() {
		return fmt.Errorf("invalid or missing digest in claim: %s", foundDgst)
	}
	return nil
}

func (sp *SignedPayload) VerifyTlog(rc *client.Rekor, publicKeyPem []byte) (string, error) {
	return findTlogEntry(rc, sp.Base64Signature, sp.Payload, publicKeyPem)
}

func (sp *SignedPayload) TrustedCert(roots *x509.CertPool) error {
	if _, err := sp.Cert.Verify(x509.VerifyOptions{
		// THIS IS IMPORTANT: WE DO NOT CHECK TIMES HERE
		// THE CERTIFICATE IS TREATED AS TRUSTED FOREVER
		// WE CHECK THAT THE SIGNATURES WERE CREATED DURING THIS WINDOW
		CurrentTime: sp.Cert.NotBefore,
		Roots:       fulcio.Roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageDigitalSignature),
			x509.ExtKeyUsageCodeSigning,
		},
	}); err != nil {
		return err
	}
	return nil
}

func correctAnnotations(wanted, have map[string]string) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
