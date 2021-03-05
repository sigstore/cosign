/*
Copyright The Rekor Authors

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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
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
		return nil, fmt.Errorf("invalid public key")
	}
	return ed, nil
}

func LoadPublicKeyFromPrivKey(pk ecdsa.PrivateKey) ([]byte, error) {
	pubKey, err := x509.MarshalPKIXPublicKey(pk.Public())
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

	if !ecdsa.VerifyASN1(pubkey, payload, signature) {
		return errors.New("unable to verify signature")
	}

	return nil
}

func Verify(ref name.Reference, pubKey *ecdsa.PublicKey, checkClaims bool, annotations map[string]string) ([]SignedPayload, error) {
	signatures, desc, err := FetchSignatures(ref)
	if err != nil {
		return nil, err
	}

	// We have a few different checks to do here:
	// 1. The signatures blobs are valid (the public key can verify the payload and signature)
	// 2. The payload blobs are in a format we understand, and the digest of the image is correct

	// 1. First find all valid signatures
	valid, err := validSignatures(pubKey, signatures)
	if err != nil {
		return nil, err
	}

	// If we're not verifying claims, just print and exit.
	if !checkClaims {
		return valid, nil
	}

	// Now we have to actually parse the payloads and make sure the digest (and other claims) are correct
	verified, err := verifyClaims(desc.Digest.String(), annotations, valid)
	if err != nil {
		return nil, err
	}

	return verified, nil
}

func validSignatures(pubKey *ecdsa.PublicKey, signatures []SignedPayload) ([]SignedPayload, error) {
	validSignatures := []SignedPayload{}
	validationErrs := []string{}

	for _, sp := range signatures {
		if err := VerifySignature(pubKey, sp.Base64Signature, sp.Payload); err != nil {
			validationErrs = append(validationErrs, err.Error())
			continue
		}
		validSignatures = append(validSignatures, sp)
	}
	// If there are none, we error.
	if len(validSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n  "))
	}
	return validSignatures, nil

}

func verifyClaims(digest string, annotations map[string]string, signatures []SignedPayload) ([]SignedPayload, error) {
	checkClaimErrs := []string{}
	// Now look through the payloads for things we understand
	verifiedPayloads := []SignedPayload{}
	for _, sp := range signatures {
		ss := SimpleSigning{}
		if err := json.Unmarshal(sp.Payload, &ss); err != nil {
			checkClaimErrs = append(checkClaimErrs, err.Error())
			continue
		}
		foundDgst := ss.Critical.Image.DockerManifestDigest
		if foundDgst != digest {
			checkClaimErrs = append(checkClaimErrs, fmt.Sprintf("invalid or missing digest in claim: %s", foundDgst))
			continue
		}
		if !correctAnnotations(annotations, ss.Optional) {
			checkClaimErrs = append(checkClaimErrs, fmt.Sprintf("invalid or missing annotation in claim: %v", ss.Optional))
			continue
		}
		verifiedPayloads = append(verifiedPayloads, sp)
	}
	if len(verifiedPayloads) == 0 {
		return nil, fmt.Errorf("no matching claims:\n%s", strings.Join(checkClaimErrs, "\n  "))
	}
	return verifiedPayloads, nil
}

func correctAnnotations(wanted, have map[string]string) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
