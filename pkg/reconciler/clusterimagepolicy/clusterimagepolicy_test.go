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
	"testing"

	"github.com/sigstore/cosign/pkg/apis/config"
	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	fakecosignclient "github.com/sigstore/cosign/pkg/client/injection/client/fake"
	"github.com/sigstore/cosign/pkg/client/injection/reconciler/cosigned/v1alpha1/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	logtesting "knative.dev/pkg/logging/testing"
	"knative.dev/pkg/system"

	. "github.com/sigstore/cosign/pkg/reconciler/testing/v1alpha1"
	. "knative.dev/pkg/reconciler/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	cipName  = "test-cip"
	testKey  = "test-cip"
	cipName2 = "test-cip-2"
	testKey2 = "test-cip-2"
	glob     = "ghcr.io/example/*"
	kms      = "azure-kms://foo/bar"

	// Just some public key that was laying around, only format matters.
	inlineKeyData = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J
RCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==
-----END PUBLIC KEY-----`

	// This is the patch for replacing a single entry in the ConfigMap
	replaceCIPPatch = `[{"op":"replace","path":"/data/test-cip","value":"{\"images\":[{\"glob\":\"ghcr.io/example/*\",\"regex\":\"\"}],\"authorities\":[{\"key\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\"}}]}"}]`

	// This is the patch for adding an entry for non-existing KMS for cipName2
	addCIP2Patch = `[{"op":"add","path":"/data/test-cip-2","value":"{\"images\":[{\"glob\":\"ghcr.io/example/*\",\"regex\":\"\"}],\"authorities\":[{\"key\":{\"data\":\"azure-kms://foo/bar\"}}]}"}]`

	// This is the patch for removing the last entry, leaving just the
	// configmap objectmeta, no data.
	removeDataPatch = `[{"op":"remove","path":"/data"}]`

	// THis is the patch for removing only a single entry from a map that has
	// two entries but only one is being removed.
	removeSingleEntryPatch = `[{"op":"remove","path":"/data/test-cip-2"}]`
)

func TestReconcile(t *testing.T) {
	table := TableTest{{
		Name: "bad workqueue key",
		// Make sure Reconcile handles bad keys.
		Key: "too/many/parts",
	}, {
		Name: "key not found",
		// Make sure Reconcile handles good keys that don't exist.
		Key: "foo/not-found",
	}, {
		Name: "ClusterImagePolicy not found",
		Key:  testKey,
	}, {
		Name: "ClusterImagePolicy is being deleted, doesn't exist, no changes",
		Key:  testKey,
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithClusterImagePolicyDeletionTimestamp),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, added to cm and finalizer",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: inlineKeyData,
					}}))},
		WantCreates: []runtime.Object{
			makeConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), cipName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip" finalizers`),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, already exists, no patch",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: inlineKeyData,
					}})),
			makeConfigMap(),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, needs a patch",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: inlineKeyData,
					}})),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replaceCIPPatch),
		},
	}, {
		Name: "ClusterImagePolicy with glob and KMS key data, added as a patch",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName2,
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: kms,
					}})),
			makeConfigMap(), // Make the existing configmap
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(addCIP2Patch),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, already exists, deleted",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: inlineKeyData,
					}}),
				WithClusterImagePolicyDeletionTimestamp),
			makeConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchRemoveFinalizers(system.Namespace(), cipName),
			makePatch(removeDataPatch),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip" finalizers`),
		},
	}, {
		Name: "Two entries, remove only one",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName2,
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: inlineKeyData,
					}}),
				WithClusterImagePolicyDeletionTimestamp),
			makeConfigMapWithTwoEntries(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchRemoveFinalizers(system.Namespace(), cipName2),
			makePatch(removeSingleEntryPatch),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip-2" finalizers`),
		},
	}, {}}

	logger := logtesting.TestLogger(t)
	table.Test(t, MakeFactory(func(ctx context.Context, listers *Listers, cmw configmap.Watcher) controller.Reconciler {
		r := &Reconciler{
			secretlister:    listers.GetSecretLister(),
			configmaplister: listers.GetConfigMapLister(),
			kubeclient:      fakekubeclient.Get(ctx),
		}
		return clusterimagepolicy.NewReconciler(ctx, logger,
			fakecosignclient.Get(ctx), listers.GetClusterImagePolicyLister(),
			controller.GetEventRecorder(ctx),
			r)
	},
		false,
		logger,
	))
}

func makeConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName: `{"images":[{"glob":"ghcr.io/example/*","regex":""}],"authorities":[{"key":{"data":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END PUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as above, just forcing an update by changing PUBLIC => NOTPUBLIC
func makeDifferentConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName: `{"images":[{"glob":"ghcr.io/example/*","regex":""}],"authorities":[{"key":{"data":"-----BEGIN NOTPUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END NOTPUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as MakeConfigMap but a placeholder for secont entry so we can remove it.
func makeConfigMapWithTwoEntries() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName:  `{"images":[{"glob":"ghcr.io/example/*","regex":""}],"authorities":[{"key":{"data":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END PUBLIC KEY-----"}}]}`,
			cipName2: "remove me please",
		},
	}
}

func makePatch(patch string) clientgotesting.PatchActionImpl {
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.ImagePoliciesConfigName,
		Patch: []byte(patch),
	}
}

func patchFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":["` + finalizerName + `"],"resourceVersion":""}}`
	action.Patch = []byte(patch)
	return action
}

func patchRemoveFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":[],"resourceVersion":""}}`
	action.Patch = []byte(patch)
	return action
}
