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

	"k8s.io/client-go/tools/cache"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	configmapinformer "knative.dev/pkg/client/injection/kube/informers/core/v1/configmap"
	secretinformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"
	pkgreconciler "knative.dev/pkg/reconciler"

	"github.com/sigstore/cosign/pkg/apis/config"
	clusterimagepolicyinformer "github.com/sigstore/cosign/pkg/client/injection/informers/cosigned/v1alpha1/clusterimagepolicy"
	clusterimagepolicyreconciler "github.com/sigstore/cosign/pkg/client/injection/reconciler/cosigned/v1alpha1/clusterimagepolicy"
)

const SystemNamespace = "cosign-system"

// NewController creates a Reconciler and returns the result of NewImpl.
func NewController(
	ctx context.Context,
	cmw configmap.Watcher,
) *controller.Impl {
	clusterimagepolicyInformer := clusterimagepolicyinformer.Get(ctx)
	cmInformer := configmapinformer.Get(ctx)
	secretInformer := secretinformer.Get(ctx)

	r := &Reconciler{
		secretlister:    secretInformer.Lister(),
		configmaplister: cmInformer.Lister(),
		kubeclient:      kubeclient.Get(ctx),
	}
	impl := clusterimagepolicyreconciler.NewImpl(ctx, r)
	r.tracker = impl.Tracker

	clusterimagepolicyInformer.Informer().AddEventHandler(controller.HandleAll(impl.Enqueue))

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
	cmInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: pkgreconciler.ChainFilterFuncs(
			pkgreconciler.NamespaceFilterFunc(SystemNamespace),
			pkgreconciler.NameFilterFunc(config.ImagePoliciesConfigName)),
		Handler: controller.HandleAll(grCb),
	})
	return impl
}
