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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"

	// Use the informer factory that restricts only to our namespace. This way
	// we won't have to grant too broad RBAC rights, nor have trouble starting
	// up if we don't have them.

	pkgreconciler "knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"

	"github.com/sigstore/cosign/pkg/apis/config"
	clusterimagepolicyinformer "github.com/sigstore/cosign/pkg/client/injection/informers/policy/v1alpha1/clusterimagepolicy"
	clusterimagepolicyreconciler "github.com/sigstore/cosign/pkg/client/injection/reconciler/policy/v1alpha1/clusterimagepolicy"
	cminformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/configmap"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
)

// This is what the default finalizer name is, but make it explicit so we can
// use it in tests as well.
const finalizerName = "clusterimagepolicies.policy.sigstore.dev"

// NewController creates a Reconciler and returns the result of NewImpl.
func NewController(
	ctx context.Context,
	cmw configmap.Watcher,
) *controller.Impl {
	clusterimagepolicyInformer := clusterimagepolicyinformer.Get(ctx)
	secretInformer := secretinformer.Get(ctx)
	configMapInformer := cminformer.Get(ctx)

	r := &Reconciler{
		secretlister:    secretInformer.Lister(),
		configmaplister: configMapInformer.Lister(),
		kubeclient:      kubeclient.Get(ctx),
	}
	impl := clusterimagepolicyreconciler.NewImpl(ctx, r, func(impl *controller.Impl) controller.Options {
		return controller.Options{FinalizerName: finalizerName}
	})
	r.tracker = impl.Tracker

	clusterimagepolicyInformer.Informer().AddEventHandler(controller.HandleAll(impl.Enqueue))

	secretInformer.Informer().AddEventHandler(controller.HandleAll(
		// Call the tracker's OnChanged method, but we've seen the objects
		// coming through this path missing TypeMeta, so ensure it is properly
		// populated.
		controller.EnsureTypeMeta(
			r.tracker.OnChanged,
			corev1.SchemeGroupVersion.WithKind("Secret"),
		),
	))

	// When the underlying ConfigMap changes,perform a global resync on
	// ClusterImagePolicies to make sure their state is correctly reflected
	// in the ConfigMap. This is admittedly a bit heavy handed, but I don't
	// really see a way around it, since if something is wrong with the
	// ConfigMap but there are no changes to the ClusterImagePolicy, it needs
	// to be synced.
	grCb := func(obj interface{}) {
		logging.FromContext(ctx).Info("Doing a global resync on ClusterImagePolicies due to ConfigMap changing.")
		impl.GlobalResync(clusterimagepolicyInformer.Informer())
	}
	// Resync on only ConfigMap changes that pertain to the one I care about.
	// We could also fetch/construct the store and use CM watcher for it, but
	// since we need a lister for it anyways in the reconciler, just set up
	// the watch here.
	configMapInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: pkgreconciler.ChainFilterFuncs(
			pkgreconciler.NamespaceFilterFunc(system.Namespace()),
			pkgreconciler.NameFilterFunc(config.ImagePoliciesConfigName)),
		Handler: controller.HandleAll(grCb),
	})
	return impl
}
