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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"knative.dev/pkg/apis"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/logging"
)

// ClusterImagePolicy defines the images that go through verification
// and the authorities used for verification.
// This is the internal representation of the external v1alpha1.ClusterImagePolicy.
// KeyRef does not store secretRefs in internal representation.
// KeyRef does store parsed publicKeys from Data in internal representation.
type ClusterImagePolicy struct {
	Images      []v1alpha1.ImagePattern `json:"images"`
	Authorities []Authority             `json:"authorities"`
	// Policy is an optional policy used to evaluate the results of valid
	// Authorities. Will not get evaluated unless at least one Authority
	// succeeds.
	Policy *AttestationPolicy `json:"policy,omitempty"`
}

type Authority struct {
	// Name is the name for this authority. Used by the CIP Policy
	// validator to be able to reference matching signature or attestation
	// verifications.
	Name string `json:"name"`
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
	RemoteOpts []ociremote.Option `json:"-"`
	// +optional
	Attestations []AttestationPolicy `json:"attestations,omitempty"`
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

type AttestationPolicy struct {
	// Name of the Attestation
	Name string `json:"name"`
	// PredicateType to attest, one of the accepted in verify-attestation
	PredicateType string `json:"predicateType"`
	// Type specifies how to evaluate policy, only rego/cue are understood.
	Type string `json:"type,omitempty"`
	// Data is the inlined version of the Policy used to evaluate the
	// Attestation.
	Data string `json:"data,omitempty"`
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
				rawAuthority.RemoteOpts = append(rawAuthority.RemoteOpts, ociremote.WithTargetRepository(targetRepoOverride))
			}
		}
	}

	// Set the new type instance to casted original
	*a = Authority(rawAuthority)
	return nil
}

func (a *Authority) SourceSignaturePullSecretsOpts(ctx context.Context, namespace string) []ociremote.Option {
	var ret []ociremote.Option
	for _, source := range a.Sources {
		if len(source.SignaturePullSecrets) > 0 {

			signaturePullSecrets := make([]string, 0, len(source.SignaturePullSecrets))
			for _, s := range source.SignaturePullSecrets {
				signaturePullSecrets = append(signaturePullSecrets, s.Name)
			}

			opt := k8schain.Options{
				Namespace:        namespace,
				ImagePullSecrets: signaturePullSecrets,
			}

			kc, err := k8schain.New(ctx, kubeclient.Get(ctx), opt)
			if err != nil {
				logging.FromContext(ctx).Errorf("failed creating keychain: %+v", err)
			}

			ret = append(ret, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
		}
	}

	return ret
}

func ConvertClusterImagePolicyV1alpha1ToWebhook(in *v1alpha1.ClusterImagePolicy) *ClusterImagePolicy {
	copyIn := in.DeepCopy()

	outAuthorities := make([]Authority, 0)
	for _, authority := range copyIn.Spec.Authorities {
		outAuthority := convertAuthorityV1Alpha1ToWebhook(authority)
		outAuthorities = append(outAuthorities, *outAuthority)
	}

	// If there's a ClusterImagePolicy level AttestationPolicy, convert it here.
	var cipAttestationPolicy *AttestationPolicy
	if in.Spec.Policy != nil {
		cipAttestationPolicy = &AttestationPolicy{
			Type: in.Spec.Policy.Type,
			Data: in.Spec.Policy.Data,
		}
	}
	return &ClusterImagePolicy{
		Images:      copyIn.Spec.Images,
		Authorities: outAuthorities,
		Policy:      cipAttestationPolicy,
	}
}

func convertAuthorityV1Alpha1ToWebhook(in v1alpha1.Authority) *Authority {
	keyRef := convertKeyRefV1Alpha1ToWebhook(in.Key)
	keylessRef := convertKeylessRefV1Alpha1ToWebhook(in.Keyless)
	attestations := convertAttestationsV1Alpha1ToWebhook(in.Attestations)

	return &Authority{
		Name:         in.Name,
		Key:          keyRef,
		Keyless:      keylessRef,
		Sources:      in.Sources,
		CTLog:        in.CTLog,
		Attestations: attestations,
	}
}

func convertAttestationsV1Alpha1ToWebhook(in []v1alpha1.Attestation) []AttestationPolicy {
	ret := []AttestationPolicy{}
	for _, inAtt := range in {
		outAtt := AttestationPolicy{
			Name:          inAtt.Name,
			PredicateType: inAtt.PredicateType,
		}
		if inAtt.Policy != nil {
			outAtt.Type = inAtt.Policy.Type
			outAtt.Data = inAtt.Policy.Data
		}
		ret = append(ret, outAtt)
	}
	return ret
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
