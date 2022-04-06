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

package clusterimagepolicy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
)

// ClusterImagePolicy defines the images that go through verification
// and the authorities used for verification.
// This is the internal representation of the external v1alpha1.ClusterImagePolicy.
// KeyRef does not store secretRefs in internal representation.
// KeyRef does store parsed publicKeys from Data in internal representation.
type ClusterImagePolicy struct {
	Images      []v1alpha1.ImagePattern `json:"images"`
	Authorities []Authority             `json:"authorities"`
}

type Authority struct {
	// +optional
	Key *KeyRef `json:"key,omitempty"`
	// +optional
	Keyless *v1alpha1.KeylessRef `json:"keyless,omitempty"`
	// +optional
	Sources []v1alpha1.Source `json:"source,omitempty"`
	// +optional
	CTLog *v1alpha1.TLog `json:"ctlog,omitempty"`
}

// This references a public verification key stored in
// a secret in the cosign-system namespace.
type KeyRef struct {
	// Data contains the inline public key
	// +optional
	Data string `json:"data,omitempty"`
	// KMS contains the KMS url of the public key
	// +optional
	KMS string `json:"kms,omitempty"`
	// PublicKeys are not marshalled because JSON unmarshalling
	// errors for *big.Int
	// +optional
	PublicKeys []*ecdsa.PublicKey `json:"-"`
}

// UnmarshalJSON populates the PublicKeys using Data because
// JSON unmashalling errors for *big.Int
func (k *KeyRef) UnmarshalJSON(data []byte) error {
	var publicKeys []*ecdsa.PublicKey
	var err error

	ret := make(map[string]string)
	if err = json.Unmarshal(data, &ret); err != nil {
		return err
	}

	k.Data = ret["data"]

	if ret["data"] != "" {
		publicKeys, err = convertKeyDataToPublicKeys(ret["data"])
		if err != nil {
			return err
		}
	}

	k.PublicKeys = publicKeys

	return nil
}

func convertKeyDataToPublicKeys(pubKey string) ([]*ecdsa.PublicKey, error) {
	keys := []*ecdsa.PublicKey{}

	pems := parsePems([]byte(pubKey))
	for _, p := range pems {
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
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
