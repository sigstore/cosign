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
	"fmt"
	"strings"

	"github.com/sigstore/cosign/pkg/apis/config"
	"github.com/sigstore/cosign/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/cosign/pkg/apis/utils"
	clusterimagepolicyreconciler "github.com/sigstore/cosign/pkg/client/injection/reconciler/policy/v1alpha1/clusterimagepolicy"
	webhookcip "github.com/sigstore/cosign/pkg/cosign/kubernetes/webhook/clusterimagepolicy"
	"github.com/sigstore/cosign/pkg/reconciler/clusterimagepolicy/resources"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"knative.dev/pkg/logging"
	"knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"
	"knative.dev/pkg/tracker"

	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
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
	cipCopy, cipErr := r.inlinePublicKeys(ctx, cip)
	if cipErr != nil {
		r.handleCIPError(ctx, cip.Name)
		// Note that we return the error about the Invalid cip here to make
		// sure that it's surfaced.
		return cipErr
	}

	webhookCIP := webhookcip.ConvertClusterImagePolicyV1alpha1ToWebhook(cipCopy)

	// See if the CM holding configs exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			return err
		}
		// Does not exist, create it.
		cm, err := resources.NewConfigMap(system.Namespace(), config.ImagePoliciesConfigName, cip.Name, webhookCIP)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to construct configmap: %v", err)
			return err
		}
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}

	// Check if we need to update the configmap or not.
	patchBytes, err := resources.CreatePatch(system.Namespace(), config.ImagePoliciesConfigName, cip.Name, existing.DeepCopy(), webhookCIP)
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
	return r.removeCIPEntry(ctx, existing, cip.Name)
}

func (r *Reconciler) handleCIPError(ctx context.Context, cipName string) {
	// The CIP is invalid, try to remove CIP from the configmap
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
		}
	} else if err := r.removeCIPEntry(ctx, existing, cipName); err != nil {
		logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
	}
}

// inlinePublicKeys will go through the CIP and try to read the referenced
// secrets, KMS keys and convert them into inlined data. Makes a copy of the CIP
// before modifying it and returns the copy.
func (r *Reconciler) inlinePublicKeys(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) (*v1alpha1.ClusterImagePolicy, error) {
	ret := cip.DeepCopy()
	for _, authority := range ret.Spec.Authorities {
		if authority.Key != nil && authority.Key.SecretRef != nil {
			if err := r.inlineAndTrackSecret(ctx, ret, authority.Key); err != nil {
				logging.FromContext(ctx).Errorf("Failed to read secret %q: %v", authority.Key.SecretRef.Name, err)
				return nil, err
			}
		}
		if authority.Keyless != nil && authority.Keyless.CACert != nil &&
			authority.Keyless.CACert.SecretRef != nil {
			if err := r.inlineAndTrackSecret(ctx, ret, authority.Keyless.CACert); err != nil {
				logging.FromContext(ctx).Errorf("Failed to read secret %q: %v", authority.Keyless.CACert.SecretRef.Name, err)
				return nil, err
			}
		}
		if authority.Key != nil && strings.Contains(authority.Key.KMS, "://") {
			pubKeyString, err := getKMSPublicKey(ctx, authority.Key.KMS)
			if err != nil {
				return nil, err
			}

			authority.Key.Data = pubKeyString
			authority.Key.KMS = ""
		}
	}
	return ret, nil
}

// getKMSPublicKey returns the public key as a string from the configured KMS service using the key ID
func getKMSPublicKey(ctx context.Context, keyID string) (string, error) {
	kmsSigner, err := kms.Get(ctx, keyID, crypto.SHA256)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to read KMS key ID %q: %v", keyID, err)
		return "", err
	}
	pemBytes, err := sigs.PublicKeyPem(kmsSigner, signatureoptions.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

// inlineSecret will take in a KeyRef and tries to read the Secret, finding the
// first key from it and will inline it in place of Data and then clear out
// the SecretRef and return it.
// Additionally, we set up a tracker so we will be notified if the secret
// is modified.
// There's still some discussion about how to handle multiple keys in a secret
// for now, just grab one from it. For reference, the discussion is here:
// TODO(vaikas): https://github.com/sigstore/cosign/issues/1573
func (r *Reconciler) inlineAndTrackSecret(ctx context.Context, cip *v1alpha1.ClusterImagePolicy, keyref *v1alpha1.KeyRef) error {
	if err := r.tracker.TrackReference(tracker.Reference{
		APIVersion: "v1",
		Kind:       "Secret",
		Namespace:  system.Namespace(),
		Name:       keyref.SecretRef.Name,
	}, cip); err != nil {
		return fmt.Errorf("failed to track changes to secret %q : %w", keyref.SecretRef.Name, err)
	}
	secret, err := r.secretlister.Secrets(system.Namespace()).Get(keyref.SecretRef.Name)
	if err != nil {
		return err
	}
	if len(secret.Data) == 0 {
		return fmt.Errorf("secret %q contains no data", keyref.SecretRef.Name)
	}
	if len(secret.Data) > 1 {
		return fmt.Errorf("secret %q contains multiple data entries, only one is supported", keyref.SecretRef.Name)
	}
	for k, v := range secret.Data {
		logging.FromContext(ctx).Infof("inlining secret %q key %q", keyref.SecretRef.Name, k)
		if !utils.IsValidKey(v) {
			return fmt.Errorf("secret %q contains an invalid public key", keyref.SecretRef.Name)
		}

		keyref.Data = string(v)
		keyref.SecretRef = nil
	}
	return nil
}

// removeCIPEntry removes an entry from a CM. If no entry exists, it's a nop.
func (r *Reconciler) removeCIPEntry(ctx context.Context, cm *corev1.ConfigMap, cipName string) error {
	patchBytes, err := resources.CreateRemovePatch(system.Namespace(), config.ImagePoliciesConfigName, cm.DeepCopy(), cipName)
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
