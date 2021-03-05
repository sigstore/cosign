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
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/encrypted"
)

const (
	pemType = "ENCRYPTED COSIGN PRIVATE KEY"
	sigkey  = "dev.cosignproject.cosign/signature"
)

func LoadPrivateKey(key []byte, pass []byte) (ecdsa.PrivateKey, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return ecdsa.PrivateKey{}, errors.New("invalid pem block")
	}
	if p.Type != pemType {
		return ecdsa.PrivateKey{}, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return ecdsa.PrivateKey{}, errors.Wrap(err, "decrypt")
	}

	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return ecdsa.PrivateKey{}, errors.Wrap(err, "parsing priv key")
	}
	typed, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return ecdsa.PrivateKey{}, fmt.Errorf("ecdsa priv key")
	}
	return *typed, nil
}

type SimpleSigning struct {
	Critical Critical
	Optional map[string]string
}

type Critical struct {
	Identity Identity
	Image    Image
	Type     string
}

type Identity struct {
	DockerReference string `json:"docker-reference"`
}

type Image struct {
	DockerManifestDigest string `json:"Docker-manifest-digest"`
}
