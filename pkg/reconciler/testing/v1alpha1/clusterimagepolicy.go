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

package testing

import (
	"context"
	"time"

	"github.com/sigstore/cosign/pkg/apis/policycontroller/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const finalizerName = "clusterimagepolicies.policycontroller.sigstore.dev"

// ClusterImagePolicyOption enables further configuration of a ClusterImagePolicy.
type ClusterImagePolicyOption func(*v1alpha1.ClusterImagePolicy)

// NewClusterImagePolicy creates a ClusterImagePolicy with ClusterImagePolicyOptions.
func NewClusterImagePolicy(name string, o ...ClusterImagePolicyOption) *v1alpha1.ClusterImagePolicy {
	cip := &v1alpha1.ClusterImagePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	for _, opt := range o {
		opt(cip)
	}
	cip.SetDefaults(context.Background())
	return cip
}

func WithClusterImagePolicyDeletionTimestamp(cip *v1alpha1.ClusterImagePolicy) {
	t := metav1.NewTime(time.Unix(1e9, 0))
	cip.ObjectMeta.SetDeletionTimestamp(&t)
}

func WithImagePattern(ip v1alpha1.ImagePattern) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Images = append(cip.Spec.Images, ip)
	}
}

func WithAuthority(a v1alpha1.Authority) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Authorities = append(cip.Spec.Authorities, a)
	}
}

func WithFinalizer(cip *v1alpha1.ClusterImagePolicy) {
	cip.Finalizers = []string{finalizerName}
}
