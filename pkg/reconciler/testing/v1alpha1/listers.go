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
// limitations under the License.package testing

package testing

import (
	"github.com/sigstore/cosign/pkg/apis/policycontroller/v1alpha1"
	fakecosignclientset "github.com/sigstore/cosign/pkg/client/clientset/versioned/fake"
	cosignlisters "github.com/sigstore/cosign/pkg/client/listers/policycontroller/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakekubeclientset "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"knative.dev/pkg/reconciler/testing"
)

var clientSetSchemes = []func(*runtime.Scheme) error{
	fakekubeclientset.AddToScheme,
	fakecosignclientset.AddToScheme,
}

type Listers struct {
	sorter testing.ObjectSorter
}

func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	for _, addTo := range clientSetSchemes {
		if addTo(scheme) != nil {
			panic("Failed to add to scheme")
		}
	}
	return scheme
}

func NewListers(objs []runtime.Object) Listers {
	scheme := runtime.NewScheme()

	for _, addTo := range clientSetSchemes {
		if addTo(scheme) != nil {
			panic("Failed to add to scheme")
		}
	}

	ls := Listers{
		sorter: testing.NewObjectSorter(scheme),
	}

	ls.sorter.AddObjects(objs...)

	return ls
}

func (l *Listers) indexerFor(obj runtime.Object) cache.Indexer {
	return l.sorter.IndexerForObjectType(obj)
}

func (l *Listers) GetKubeObjects() []runtime.Object {
	return l.sorter.ObjectsForSchemeFunc(fakekubeclientset.AddToScheme)
}

func (l *Listers) GetCosignObjects() []runtime.Object {
	return l.sorter.ObjectsForSchemeFunc(fakecosignclientset.AddToScheme)
}

func (l *Listers) GetAllObjects() []runtime.Object {
	all := l.GetCosignObjects()
	all = append(all, l.GetKubeObjects()...)
	return all
}

func (l *Listers) GetClusterImagePolicyLister() cosignlisters.ClusterImagePolicyLister {
	return cosignlisters.NewClusterImagePolicyLister(l.indexerFor(&v1alpha1.ClusterImagePolicy{}))
}

func (l *Listers) GetSecretLister() corev1listers.SecretLister {
	return corev1listers.NewSecretLister(l.indexerFor(&corev1.Secret{}))
}

func (l *Listers) GetConfigMapLister() corev1listers.ConfigMapLister {
	return corev1listers.NewConfigMapLister(l.indexerFor(&corev1.ConfigMap{}))
}
