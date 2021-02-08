/*
Copyright The Cosign Authors.

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

package pkg

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/theupdateframework/go-tuf/encrypted"
)

const (
	pemType = "ENCRYPTED COSIGN PRIVATE KEY"
	sigkey  = "dev.cosignproject.cosign/signature"
)

func LoadPrivateKey(keyPath string, pass []byte) (ed25519.PrivateKey, error) {
	b, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// Decrypt first
	p, _ := pem.Decode(b)
	if p.Type != pemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	priv, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(priv), nil
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
