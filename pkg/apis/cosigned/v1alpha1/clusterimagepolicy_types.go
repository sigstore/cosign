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
	Images []ImagePattern `json:"images"`
}

// ImagePattern defines a pattern and its associated authorties
// If multiple patterns match a particular image, then ALL of
// those authorities must be satisfied for the image to be admitted.
type ImagePattern struct {
	Glob        string      `json:"glob"`
	Regex       string      `json:"regex"`
	Authorities []Authority `json:"authorities"`
}

// The authorities block defines the rules for discovering and
// validating signatures.  Signatures are
// cryptographically verified using one of the "key" or "keyless"
// fields.
// When multiple authorities are specified, any of them may be used
// to source the valid signature we are looking for to admit an
// image.

type Authority struct {
	Key     KeyRef     `json:"key"`
	Keyless KeylessRef `json:"keyless"`
	Sources []Source   `json:"source"`
	CTLog   TLog       `json:"ctlog"`
}

// This references a public verification key stored in
// a secret in the cosign-system namespace.
type KeyRef struct {
	SecretRef *v1.SecretReference `json:"secretref"`
	// Data contains the inline public key
	Data string `json:"data"`
	// KMS contains the KMS url of the public key
	KMS string `json:"kms"`
}

// Source specifies the location of the signature
type Source struct {
	OCI string `json:"oci"`
}

// TLog specifies the URL to a transparency log that holds
// the signature and public key information
type TLog struct {
	URL string `json:"url"`
}

// KeylessRef contains location of the validating certificate and the identities
// against which to verify. KeylessRef will contain either the URL to the verifying
// certificate, or it will contain the certificate data inline or in a secret.
type KeylessRef struct {
	URL        string             `json:"url"`
	Identities []Identity         `json:"identities"`
	CAKey      CAKey              `json:"ca-key"`
	CAKeyRef   v1.SecretReference `json:"ca-keyref"`
}

// Identity may contain the issue and/or the subject found in the transparency log.
// Either field supports a pattern glob.
type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// CAKey contains inline public-key data
type CAKey struct {
	// Name is an arbitrary identifier for this key for human consumption
	Name string `json:"name"`
	// Data contains inline certificate data
	Data string `json:"data"`
}

// ClusterImagePolicyList is a list of ClusterImagePolicy resources
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterImagePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterImagePolicy `json:"items"`
}