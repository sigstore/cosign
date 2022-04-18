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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	"github.com/sigstore/cosign/pkg/oci/remote"

	"knative.dev/pkg/apis"
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
	Keyless *KeylessRef `json:"keyless,omitempty"`
	// +optional
	Sources []v1alpha1.Source `json:"source,omitempty"`
	// +optional
	CTLog *v1alpha1.TLog `json:"ctlog,omitempty"`
	// RemoteOpts are not marshalled because they are an unsupported type
	// RemoteOpts will be populated by the Authority UnmarshalJSON override
	// +optional
	RemoteOpts []remote.Option `json:"-"`
}

// This references a public verification key stored in
// a secret in the cosign-system namespace.
type KeyRef struct {
	// Data contains the inline public key
	// +optional
	Data string `json:"data,omitempty"`
	// PublicKeys are not marshalled because JSON unmarshalling
	// errors for *big.Int
	// +optional
	PublicKeys []crypto.PublicKey `json:"-"`
}

type KeylessRef struct {
	// +optional
	URL *apis.URL `json:"url,omitempty"`
	// +optional
	Identities []v1alpha1.Identity `json:"identities,omitempty"`
	// +optional
	CACert *KeyRef `json:"ca-cert,omitempty"`
}

// UnmarshalJSON populates the PublicKeys using Data because
// JSON unmashalling errors for *big.Int
func (k *KeyRef) UnmarshalJSON(data []byte) error {
	var publicKeys []crypto.PublicKey
	var err error

	ret := make(map[string]string)
	if err = json.Unmarshal(data, &ret); err != nil {
		return err
	}

	k.Data = ret["data"]

	if ret["data"] != "" {
		publicKeys, err = ConvertKeyDataToPublicKeys(ret["data"])
		if err != nil {
			return err
		}
	}

	k.PublicKeys = publicKeys

	return nil
}

// UnmarshalJSON populates the authority with the remoteOpts
// from authority sources
func (a *Authority) UnmarshalJSON(data []byte) error {
	// Create a new type to avoid recursion
	type RawAuthority Authority

	var rawAuthority RawAuthority
	err := json.Unmarshal(data, &rawAuthority)
	if err != nil {
		return err
	}

	// Determine additional RemoteOpts
	if len(rawAuthority.Sources) > 0 {
		for _, source := range rawAuthority.Sources {
			if targetRepoOverride, err := name.NewRepository(source.OCI); err != nil {
				return errors.Wrap(err, "failed to determine source")
			} else if (targetRepoOverride != name.Repository{}) {
				rawAuthority.RemoteOpts = append(rawAuthority.RemoteOpts, remote.WithTargetRepository(targetRepoOverride))
			}
		}
	}

	// Set the new type instance to casted original
	*a = Authority(rawAuthority)
	return nil
}

func ConvertClusterImagePolicyV1alpha1ToWebhook(in *v1alpha1.ClusterImagePolicy) *ClusterImagePolicy {
	copyIn := in.DeepCopy()

	outAuthorities := make([]Authority, 0)
	for _, authority := range copyIn.Spec.Authorities {
		outAuthority := convertAuthorityV1Alpha1ToWebhook(authority)
		outAuthorities = append(outAuthorities, *outAuthority)
	}

	return &ClusterImagePolicy{
		Images:      copyIn.Spec.Images,
		Authorities: outAuthorities,
	}
}

func convertAuthorityV1Alpha1ToWebhook(in v1alpha1.Authority) *Authority {
	keyRef := convertKeyRefV1Alpha1ToWebhook(in.Key)
	keylessRef := convertKeylessRefV1Alpha1ToWebhook(in.Keyless)

	return &Authority{
		Key:     keyRef,
		Keyless: keylessRef,
		Sources: in.Sources,
		CTLog:   in.CTLog,
	}
}

func convertKeyRefV1Alpha1ToWebhook(in *v1alpha1.KeyRef) *KeyRef {
	if in == nil {
		return nil
	}

	return &KeyRef{
		Data: in.Data,
	}
}

func convertKeylessRefV1Alpha1ToWebhook(in *v1alpha1.KeylessRef) *KeylessRef {
	if in == nil {
		return nil
	}

	CACertRef := convertKeyRefV1Alpha1ToWebhook(in.CACert)

	return &KeylessRef{
		URL:        in.URL,
		Identities: in.Identities,
		CACert:     CACertRef,
	}
}

func parsePEMKey(b []byte) ([]*pem.Block, bool) {
	pemKey, rest := pem.Decode(b)
	valid := true
	if pemKey == nil {
		return nil, false
	}
	pemBlocks := []*pem.Block{pemKey}

	if len(rest) > 0 {
		list, check := parsePEMKey(rest)
		return append(pemBlocks, list...), check
	}
	return pemBlocks, valid
}

func ConvertKeyDataToPublicKeys(pubKey string) ([]crypto.PublicKey, error) {
	keys := []crypto.PublicKey{}
	pems, validPEM := parsePEMKey([]byte(pubKey))
	if !validPEM {
		// TODO: If it is not valid report the error instead of ignore the key
		return keys, nil
	}

	for _, p := range pems {
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key.(crypto.PublicKey))
	}

	return keys, nil
}
