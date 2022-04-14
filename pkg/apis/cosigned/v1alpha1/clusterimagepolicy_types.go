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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/kmeta"
)

// ClusterImagePolicy defines the images that go through verification
// and the authorities used for verification
//
// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +genreconciler:krshapedlogic=false

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterImagePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec holds the desired state of the ClusterImagePolicy (from the client).
	Spec ClusterImagePolicySpec `json:"spec"`
}

var (
	_ apis.Validatable   = (*ClusterImagePolicy)(nil)
	_ apis.Defaultable   = (*ClusterImagePolicy)(nil)
	_ kmeta.OwnerRefable = (*ClusterImagePolicy)(nil)
)

// GetGroupVersionKind implements kmeta.OwnerRefable
func (*ClusterImagePolicy) GetGroupVersionKind() schema.GroupVersionKind {
	return SchemeGroupVersion.WithKind("ClusterImagePolicy")
}

// ClusterImagePolicySpec defines a list of images that should be verified
type ClusterImagePolicySpec struct {
	Images      []ImagePattern `json:"images"`
	Authorities []Authority    `json:"authorities"`
}

// ImagePattern defines a pattern and its associated authorties
// If multiple patterns match a particular image, then ALL of
// those authorities must be satisfied for the image to be admitted.
type ImagePattern struct {
	// +optional
	Glob string `json:"glob,omitempty"`
	// +optional
	Regex string `json:"regex,omitempty"`
}

// The authorities block defines the rules for discovering and
// validating signatures.  Signatures are
// cryptographically verified using one of the "key" or "keyless"
// fields.
// When multiple authorities are specified, any of them may be used
// to source the valid signature we are looking for to admit an
// image.

type Authority struct {
	// Name is the name for this authority. Used by the CIP Policy
	// validator to be able to reference matching signature or attestation
	// verifications.
	// If not specified, the name will be attestation-<index in array>
	Name string `json:"name"`
	// +optional
	Key *KeyRef `json:"key,omitempty"`
	// +optional
	Keyless *KeylessRef `json:"keyless,omitempty"`
	// +optional
	Sources []Source `json:"source,omitempty"`
	// +optional
	CTLog *TLog `json:"ctlog,omitempty"`
	// +optional
	Attestations []Attestation `json:"attestations,omitempty"`
}

// This references a public verification key stored in
// a secret in the cosign-system namespace.
// A KeyRef must specify only one of SecretRef, Data or KMS
type KeyRef struct {
	// +optional
	SecretRef *v1.SecretReference `json:"secretRef,omitempty"`
	// Data contains the inline public key
	// +optional
	Data string `json:"data,omitempty"`
	// KMS contains the KMS url of the public key
	// +optional
	KMS string `json:"kms,omitempty"`
}

// Source specifies the location of the signature
type Source struct {
	// +optional
	OCI string `json:"oci,omitempty"`
}

// TLog specifies the URL to a transparency log that holds
// the signature and public key information
type TLog struct {
	// +optional
	URL *apis.URL `json:"url,omitempty"`
}

// KeylessRef contains location of the validating certificate and the identities
// against which to verify. KeylessRef will contain either the URL to the verifying
// certificate, or it will contain the certificate data inline or in a secret.
type KeylessRef struct {
	// +optional
	URL *apis.URL `json:"url,omitempty"`
	// +optional
	Identities []Identity `json:"identities,omitempty"`
	// +optional
	CACert *KeyRef `json:"ca-cert,omitempty"`
}

// Attestation defines the type of attestation to validate and optionally
// apply a policy decision to it. Authority block is used to verify the
// specified attestation types, and if Policy is specified, then it's applied
// only after the validation of the Attestation signature has been verified.
type Attestation struct {
	// Which predicate type to verify. Matches cosign verify-attestation options.
	PredicateType string  `json:"predicateType"`
	Policy        *Policy `json:"policy,omitempty"`
}

// Policy specifies a policy to use for Attestation validation.
// Exactly one of Data, URL, or ConfigMapReference must be specified.
type Policy struct {
	// Which kind of policy this is, currently only rego or cue are supported.
	// Furthermore, only cue is tested :)
	Type string `json:"type"`
	// +optional
	Data string `json:"data,omitempty"`
	// +optional
	URL *apis.URL `json:"url,omitempty"`
	// +optional
	ConfigMapRef *ConfigMapReference `json:"configMapRef,omitempty"`
}

// ConfigMapReference is cut&paste from SecretReference, but for the life of me
// couldn't find one in the public types. If there's one, use it.
type ConfigMapReference struct {
	// Name is unique within a namespace to reference a configmap resource.
	// +optional
	Name string `json:"name,omitempty"`
	// Namespace defines the space within which the configmap name must be unique.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// Identity may contain the issuer and/or the subject found in the transparency log.
// Either field supports a pattern glob.
type Identity struct {
	// +optional
	Issuer string `json:"issuer,omitempty"`
	// +optional
	Subject string `json:"subject,omitempty"`
}

// ClusterImagePolicyList is a list of ClusterImagePolicy resources
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterImagePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterImagePolicy `json:"items"`
}
