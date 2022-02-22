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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/kmeta"
)

// ClusterImagePolicy defines...
//
// +genclient
// +genclient:nonNamespaced
// +genreconciler:krshapedlogic=false
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterImagePolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec holds the desired state of the ClusterImagePolicy (from the client).
	// +optional
	Spec ClusterImagePolicySpec `json:"spec,omitempty"`
}

var (
	// Check that ClusterImagePolicy can be validated and defaulted.
	_ apis.Validatable   = (*ClusterImagePolicy)(nil)
	_ apis.Defaultable   = (*ClusterImagePolicy)(nil)
	_ kmeta.OwnerRefable = (*ClusterImagePolicy)(nil)
)

// GetGroupVersionKind implements kmeta.OwnerRefable
func (*ClusterImagePolicy) GetGroupVersionKind() schema.GroupVersionKind {
	return SchemeGroupVersion.WithKind("ClusterImagePolicy")
}

// ClusterImagePolicySpec holds the desired state of the ClusterImagePolicy (from the client).
type ClusterImagePolicySpec struct {
	// TODO(#1417): Flesh out the specification from the API spec.
}

// ClusterImagePolicyList is a list of ClusterImagePolicy resources
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterImagePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterImagePolicy `json:"items"`
}
