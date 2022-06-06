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
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sigstore/cosign/pkg/apis/policy/v1beta1"
)

// Test v1alpha1 -> v1beta1 -> v1alpha1
func TestConversionRoundTripV1alpha1(t *testing.T) {
	tests := []struct {
		name string
		in   *ClusterImagePolicy
	}{{name: "key and keyless",
		in: &ClusterImagePolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cip",
			},
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{Key: &KeyRef{
						SecretRef: &v1.SecretReference{Name: "mysecret"}}},
					{Keyless: &KeylessRef{
						Identities: []Identity{{Subject: "subject", Issuer: "issuer"}},
						CACert:     &KeyRef{KMS: "kms", Data: "data", SecretRef: &v1.SecretReference{Name: "secret"}},
					}},
				},
			},
		},
	}, {name: "key and keyless, regexp",
		in: &ClusterImagePolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cip",
			},
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{Key: &KeyRef{
						SecretRef: &v1.SecretReference{Name: "mysecret"}}},
					{Keyless: &KeylessRef{
						Identities: []Identity{{SubjectRegExp: "subjectregexp", IssuerRegExp: "issuerregexp"}},
						CACert:     &KeyRef{KMS: "kms", Data: "data", SecretRef: &v1.SecretReference{Name: "secret"}},
					}},
				},
			},
		},
	}, {name: "source and attestations",
		in: &ClusterImagePolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cip",
			},
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{Key: &KeyRef{
						SecretRef: &v1.SecretReference{Name: "mysecret"}}},
					{Sources: []Source{{
						OCI:                  "registry.example.com",
						SignaturePullSecrets: []v1.LocalObjectReference{{Name: "sps-secret"}}}}},
					{Attestations: []Attestation{{
						Name:          "attestation-0",
						PredicateType: "vuln",
						Policy: &Policy{
							Type: "cue",
							Data: "cue language goes here",
						},
					}}},
				},
			},
		},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ver := &v1beta1.ClusterImagePolicy{}
			if err := test.in.ConvertTo(context.Background(), ver); err != nil {
				t.Error("ConvertTo() =", err)
			}
			got := &ClusterImagePolicy{}
			if err := got.ConvertFrom(context.Background(), ver); err != nil {
				t.Error("ConvertFrom() =", err)
			}

			if diff := cmp.Diff(test.in, got); diff != "" {
				t.Error("roundtrip (-want, +got) =", diff)
			}
		})
	}
}

// Test v1beta1 -> v1alpha1 -> v1beta1
func TestConversionRoundTripV1beta1(t *testing.T) {
	tests := []struct {
		name string
		in   *v1beta1.ClusterImagePolicy
	}{{name: "simple configuration",
		in: &v1beta1.ClusterImagePolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cip",
			},
			Spec: v1beta1.ClusterImagePolicySpec{
				Images: []v1beta1.ImagePattern{{Glob: "*"}},
			},
		},
	}, {name: "another",
		in: &v1beta1.ClusterImagePolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cip",
			},
		},
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ver := &ClusterImagePolicy{}
			if err := ver.ConvertFrom(context.Background(), test.in); err != nil {
				t.Error("ConvertDown() =", err)
			}
			got := &v1beta1.ClusterImagePolicy{}
			if err := ver.ConvertTo(context.Background(), got); err != nil {
				t.Error("ConvertUp() =", err)
			}

			if diff := cmp.Diff(test.in, got); diff != "" {
				t.Error("roundtrip (-want, +got) =", diff)
			}
		})
	}
}
