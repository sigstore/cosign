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

package v1alpha1

import (
	"context"
	"fmt"

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1beta1"
	v1 "k8s.io/api/core/v1"
	"knative.dev/pkg/apis"
)

var _ apis.Convertible = (*ClusterImagePolicy)(nil)

// ConvertTo implements api.Convertible
func (cip *ClusterImagePolicy) ConvertTo(ctx context.Context, obj apis.Convertible) error {
	switch sink := obj.(type) {
	case *v1beta1.ClusterImagePolicy:
		sink.ObjectMeta = cip.ObjectMeta
		return cip.Spec.ConvertTo(ctx, &sink.Spec)
	default:
		return fmt.Errorf("unknown version, got: %T", sink)
	}
}

// ConvertFrom implements api.Convertible
func (cip *ClusterImagePolicy) ConvertFrom(ctx context.Context, obj apis.Convertible) error {
	switch source := obj.(type) {
	case *v1beta1.ClusterImagePolicy:
		cip.ObjectMeta = source.ObjectMeta
		return cip.Spec.ConvertFrom(ctx, &source.Spec)
	default:
		return fmt.Errorf("unknown version, got: %T", cip)
	}
}

func (cips *ClusterImagePolicySpec) ConvertTo(ctx context.Context, sink *v1beta1.ClusterImagePolicySpec) error {
	for _, image := range cips.Images {
		sink.Images = append(sink.Images, v1beta1.ImagePattern{Glob: image.Glob})
	}
	for _, authority := range cips.Authorities {
		v1beta1Authority := v1beta1.Authority{}
		err := authority.ConvertTo(ctx, &v1beta1Authority)
		if err != nil {
			return err
		}
		sink.Authorities = append(sink.Authorities, v1beta1Authority)
	}
	return nil
}

func (auth *Authority) ConvertTo(ctx context.Context, sink *v1beta1.Authority) error {
	sink.Name = auth.Name
	if auth.CTLog != nil && auth.CTLog.URL != nil {
		sink.CTLog = &v1beta1.TLog{URL: auth.CTLog.URL.DeepCopy()}
	}
	for _, source := range auth.Sources {
		v1beta1Source := v1beta1.Source{}
		v1beta1Source.OCI = source.OCI
		for _, sps := range source.SignaturePullSecrets {
			v1beta1Source.SignaturePullSecrets = append(v1beta1Source.SignaturePullSecrets, v1.LocalObjectReference{Name: sps.Name})
		}
		sink.Sources = append(sink.Sources, v1beta1Source)
	}
	for _, att := range auth.Attestations {
		v1beta1Att := v1beta1.Attestation{}
		v1beta1Att.Name = att.Name
		v1beta1Att.PredicateType = att.PredicateType
		if att.Policy != nil {
			v1beta1Att.Policy = &v1beta1.Policy{
				Type: att.Policy.Type,
				Data: att.Policy.Data,
			}
			v1beta1Att.Policy.URL = att.Policy.URL.DeepCopy()
			if att.Policy.ConfigMapRef != nil {
				v1beta1Att.Policy.ConfigMapRef = &v1beta1.ConfigMapReference{
					Name:      att.Policy.ConfigMapRef.Name,
					Namespace: att.Policy.ConfigMapRef.Namespace,
				}
			}
		}
		sink.Attestations = append(sink.Attestations, v1beta1Att)
	}
	if auth.Key != nil {
		sink.Key = &v1beta1.KeyRef{}
		auth.Key.ConvertTo(ctx, sink.Key)
	}
	if auth.Keyless != nil {
		sink.Keyless = &v1beta1.KeylessRef{
			URL: auth.Keyless.URL.DeepCopy(),
		}
		for _, id := range auth.Keyless.Identities {
			sink.Keyless.Identities = append(sink.Keyless.Identities, v1beta1.Identity{Issuer: id.Issuer, Subject: id.Subject})
		}
		if auth.Keyless.CACert != nil {
			sink.Keyless.CACert = &v1beta1.KeyRef{}
			auth.Keyless.CACert.ConvertTo(ctx, sink.Keyless.CACert)
		}
	}
	return nil
}

func (key *KeyRef) ConvertTo(ctx context.Context, sink *v1beta1.KeyRef) {
	sink.SecretRef = key.SecretRef.DeepCopy()
	sink.Data = key.Data
	sink.KMS = key.KMS
}

func (cips *ClusterImagePolicySpec) ConvertFrom(ctx context.Context, source *v1beta1.ClusterImagePolicySpec) error {
	for _, image := range source.Images {
		cips.Images = append(cips.Images, ImagePattern{Glob: image.Glob})
	}
	for _, sourceAuth := range source.Authorities {
		authority := Authority{}
		err := authority.ConvertFrom(ctx, &sourceAuth)
		if err != nil {
			return err
		}
		cips.Authorities = append(cips.Authorities, authority)
	}
	return nil
}

func (auth *Authority) ConvertFrom(ctx context.Context, source *v1beta1.Authority) error {
	auth.Name = source.Name
	if source.CTLog != nil && source.CTLog.URL != nil {
		auth.CTLog = &TLog{URL: source.CTLog.URL.DeepCopy()}
	}
	for _, s := range source.Sources {
		src := Source{}
		src.OCI = s.OCI
		for _, sps := range s.SignaturePullSecrets {
			src.SignaturePullSecrets = append(src.SignaturePullSecrets, v1.LocalObjectReference{Name: sps.Name})
		}
		auth.Sources = append(auth.Sources, src)
	}
	for _, att := range source.Attestations {
		attestation := Attestation{}
		attestation.Name = att.Name
		attestation.PredicateType = att.PredicateType
		if att.Policy != nil {
			attestation.Policy = &Policy{
				Type: att.Policy.Type,
				Data: att.Policy.Data,
			}
			attestation.Policy.URL = att.Policy.URL.DeepCopy()
			if att.Policy.ConfigMapRef != nil {
				attestation.Policy.ConfigMapRef = &ConfigMapReference{
					Name:      att.Policy.ConfigMapRef.Name,
					Namespace: att.Policy.ConfigMapRef.Namespace,
				}
			}
		}
		auth.Attestations = append(auth.Attestations, attestation)
	}
	if source.Key != nil {
		auth.Key = &KeyRef{}
		auth.Key.ConvertFrom(ctx, source.Key)
	}
	if source.Keyless != nil {
		auth.Keyless = &KeylessRef{
			URL: source.Keyless.URL.DeepCopy(),
		}
		for _, id := range source.Keyless.Identities {
			auth.Keyless.Identities = append(auth.Keyless.Identities, Identity{Issuer: id.Issuer, Subject: id.Subject})
		}
		if source.Keyless.CACert != nil {
			auth.Keyless.CACert = &KeyRef{}
			auth.Keyless.CACert.ConvertFrom(ctx, source.Keyless.CACert)
		}
	}
	return nil
}

func (key *KeyRef) ConvertFrom(ctx context.Context, source *v1beta1.KeyRef) {
	key.SecretRef = source.SecretRef.DeepCopy()
	key.Data = source.Data
	key.KMS = source.KMS
}
