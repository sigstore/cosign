// Copyright 2021 The Sigstore Authors.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterImagePolicySpec defines the desired state of ImagePolicy
type ClusterImagePolicySpec struct {
	// +kubebuilder:validation:Required
	// Verification defines the requirements for the admission of a signed container image.
	Verification Verification `json:"verification"`
}
type Verification struct {
	// Used for excluding resources to which the policy should not be applied
	// +optional
	Exclude Exclude `json:"exclude,omitempty"`

	// +kubebuilder:validation:MinItems=1
	// Keys is a list of public keys that will be used to validate the image signature.
	Keys []Key `json:"keys"`

	// +kubebuilder:validation:MinItems=1
	// Images is list of images that are going to be considered for this policy.
	Images []Image `json:"images"`
}

type Exclude struct {
	// Resouces is used to specify the resource that needs to be excluded
	Resources Resources `json:"resources,omitempty"`
}

type Resources struct {
	// Namespaces is used to specify the names of the namespaces that need to be excluded
	Namespaces []string `json:"namespaces,omitempty"`
}

type Key struct {
	// Name defines a name of the key.
	Name string `json:"name"`
	// PublicKey contains the content of the public key for signing.
	PublicKey string `json:"publicKey"`
}

type KeyToImageMapping struct {
	// Name is the name of the initial signing key.
	Name string `json:"name"`
}

type Image struct {

	// +kubebuilder:validation:Required
	// NamePattern defines the image name pattern as a (e.g. `registry/path/to/image`).
	NamePattern string `json:"namePattern"`

	// +kubebuilder:validation:MinItems=1
	// Keys is a map with the references to the signing keys.
	Keys []KeyToImageMapping `json:"keys"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:path=clusterimagepolicies,scope=Cluster

// ClusterImagePolicy is the Schema for the imagepolicies API
type ClusterImagePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterImagePolicySpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterImagePolicyList contains a list of ClusterImagePolicy
type ClusterImagePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterImagePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterImagePolicy{}, &ClusterImagePolicyList{})
}
