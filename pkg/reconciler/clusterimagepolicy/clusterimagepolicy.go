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
	"errors"

	"github.com/sigstore/cosign/pkg/apis/config"
	"k8s.io/apimachinery/pkg/types"

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	clusterimagepolicyreconciler "github.com/sigstore/cosign/pkg/client/injection/reconciler/cosigned/v1alpha1/clusterimagepolicy"
	"github.com/sigstore/cosign/pkg/reconciler/clusterimagepolicy/resources"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"
	"knative.dev/pkg/tracker"
)

// Reconciler implements clusterimagepolicyreconciler.Interface for
// ClusterImagePolicy resources.
type Reconciler struct {
	// Tracker builds an index of what resources are watching other resources
	// so that we can immediately react to changes tracked resources.
	tracker tracker.Interface
	// We need to be able to read Secrets, which are really holding public
	// keys.
	secretlister    corev1listers.SecretLister
	configmaplister corev1listers.ConfigMapLister
	kubeclient      kubernetes.Interface
}

// Check that our Reconciler implements Interface as well as finalizer
var _ clusterimagepolicyreconciler.Interface = (*Reconciler)(nil)
var _ clusterimagepolicyreconciler.Finalizer = (*Reconciler)(nil)

// ReconcileKind implements Interface.ReconcileKind.
func (r *Reconciler) ReconcileKind(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) reconciler.Event {
	if !willItBlend(cip) {
		return errors.New("i can't do that yet, only support keys inlined or KMS")
	}
	// See if the CM holding configs exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			return err
		}
		// Does not exist, create it.
		cm, err := resources.NewConfigMap(system.Namespace(), config.ImagePoliciesConfigName, cip)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to construct configmap: %v", err)
			return err
		}
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}

	// Check if we need to update the configmap or not.
	patchBytes, err := resources.CreatePatch(system.Namespace(), config.ImagePoliciesConfigName, existing.DeepCopy(), cip)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create patch: %v", err)
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.ImagePoliciesConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		return err
	}
	return nil
}

// FinalizeKind implements Interface.ReconcileKind.
func (r *Reconciler) FinalizeKind(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) reconciler.Event {
	// See if the CM holding configs even exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			// There's very little we can do here. This could happen if it's
			// intermittent error, which is fine when we retry. But if something
			// goofy happens like we lost access to it, then it's a bit of a
			// pickle since the entry will exist there and we can't remove it.
			// So keep trying. Other option would be just to bail.
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			return err
		}
		// Since the CM doesn't exist, there's nothing for us to clean up.
		return nil
	}
	// CM exists, so remove our entry from it.
	patchBytes, err := resources.CreateRemovePatch(system.Namespace(), config.ImagePoliciesConfigName, existing.DeepCopy(), cip)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create remove patch: %v", err)
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.ImagePoliciesConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		return err
	}
	return nil
}

// Checks to see if we can deal with format yet. This is missing support
// for things like Secret resolution, so we can't do those yet. As more things
// are supported, remove them from here.
func willItBlend(cip *v1alpha1.ClusterImagePolicy) bool {
	for _, image := range cip.Spec.Images {
		for _, authority := range image.Authorities {
			if authority.Key != nil && authority.Key.SecretRef != nil {
				return false
			}
			if authority.Keyless != nil && authority.Keyless.CAKey != nil &&
				authority.Keyless.CAKey.SecretRef != nil {
				return false
			}
		}
	}
	return true
}
