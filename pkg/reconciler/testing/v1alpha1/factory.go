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
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/logging"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/client-go/tools/record"

	"go.uber.org/zap"
	ktesting "k8s.io/client-go/testing"
	"knative.dev/pkg/controller"

	fakecosignclient "github.com/sigstore/cosign/pkg/client/injection/client/fake"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	fakedynamicclient "knative.dev/pkg/injection/clients/dynamicclient/fake"

	"knative.dev/pkg/reconciler"
	reconcilertesting "knative.dev/pkg/reconciler/testing"
)

const (
	// maxEventBufferSize is the estimated max number of event notifications that
	// can be buffered during reconciliation.
	maxEventBufferSize = 10
)

// Ctor functions create a k8s controller with given params.
type Ctor func(context.Context, *Listers, configmap.Watcher) controller.Reconciler

// MakeFactory creates a reconciler factory with fake clients and controller created by `ctor`.
func MakeFactory(ctor Ctor, unstructured bool, logger *zap.SugaredLogger) reconcilertesting.Factory {
	return func(t *testing.T, r *reconcilertesting.TableRow) (controller.Reconciler, reconcilertesting.ActionRecorderList, reconcilertesting.EventList) {
		ls := NewListers(r.Objects)

		var ctx context.Context
		if r.Ctx != nil {
			ctx = r.Ctx
		} else {
			ctx = context.Background()
		}
		ctx = logging.WithLogger(ctx, logger)

		ctx, kubeClient := fakekubeclient.With(ctx, ls.GetKubeObjects()...)
		ctx, client := fakecosignclient.With(ctx, ls.GetCosignObjects()...)
		ctx, dynamicClient := fakedynamicclient.With(ctx,
			NewScheme(), ToUnstructured(t, r.Objects)...)
		ctx = context.WithValue(ctx, TrackerKey, &reconcilertesting.FakeTracker{})

		// The dynamic client's support for patching is BS.  Implement it
		// here via PrependReactor (this can be overridden below by the
		// provided reactors).
		dynamicClient.PrependReactor("patch", "*",
			func(action ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, nil
			})

		eventRecorder := record.NewFakeRecorder(maxEventBufferSize)
		ctx = controller.WithEventRecorder(ctx, eventRecorder)

		// Check the config maps in objects and add them to the fake cm watcher
		var cms []*corev1.ConfigMap
		for _, obj := range r.Objects {
			if cm, ok := obj.(*corev1.ConfigMap); ok {
				cms = append(cms, cm)
			}
		}
		configMapWatcher := configmap.NewStaticWatcher(cms...)

		// Set up our Controller from the fakes.
		c := ctor(ctx, &ls, configMapWatcher)
		r.Ctx = ctx
		// If the reconcilers is leader aware, then promote it.
		if la, ok := c.(reconciler.LeaderAware); ok {
			if la.Promote(reconciler.UniversalBucket(), func(reconciler.Bucket, types.NamespacedName) {}) != nil {
				panic("failed to leader promote")
			}
		}

		for _, reactor := range r.WithReactors {
			kubeClient.PrependReactor("*", "*", reactor)
			client.PrependReactor("*", "*", reactor)
			dynamicClient.PrependReactor("*", "*", reactor)
		}

		// Validate all Create and Update operations
		client.PrependReactor("create", "*", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
			return reconcilertesting.ValidateCreates(ctx, action)
		})
		client.PrependReactor("update", "*", func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
			return reconcilertesting.ValidateUpdates(ctx, action)
		})

		actionRecorderList := reconcilertesting.ActionRecorderList{dynamicClient, client, kubeClient}
		eventList := reconcilertesting.EventList{Recorder: eventRecorder}

		return c, actionRecorderList, eventList
	}
}

// ToUnstructured takes a list of k8s resources and converts them to
// Unstructured objects.
// We must pass objects as Unstructured to the dynamic client fake, or it
// won't handle them properly.
func ToUnstructured(t *testing.T, objs []runtime.Object) (us []runtime.Object) {
	sch := NewScheme()
	for _, obj := range objs {
		obj = obj.DeepCopyObject() // Don't mess with the primary copy
		// Determine and set the TypeMeta for this object based on our test scheme.
		gvks, _, err := sch.ObjectKinds(obj)
		if err != nil {
			t.Fatal("Unable to determine kind for type:", err)
		}
		apiv, k := gvks[0].ToAPIVersionAndKind()
		ta, err := meta.TypeAccessor(obj)
		if err != nil {
			t.Fatal("Unable to create type accessor:", err)
		}
		ta.SetAPIVersion(apiv)
		ta.SetKind(k)

		b, err := json.Marshal(obj)
		if err != nil {
			t.Fatal("Unable to marshal:", err)
		}
		u := &unstructured.Unstructured{}
		if err := json.Unmarshal(b, u); err != nil {
			t.Fatal("Unable to unmarshal:", err)
		}
		us = append(us, u)
	}
	return
}

type key struct{}

// TrackerKey is used to looking a FakeTracker in a context.Context
var TrackerKey key = struct{}{}

// AssertTrackingSecret will ensure the provided Secret is being tracked
func AssertTrackingSecret(namespace, name string) func(*testing.T, *reconcilertesting.TableRow) {
	gvk := corev1.SchemeGroupVersion.WithKind("Secret")
	return AssertTrackingObject(gvk, namespace, name)
}

// AssertTrackingObject will ensure the following objects are being tracked
func AssertTrackingObject(gvk schema.GroupVersionKind, namespace, name string) func(*testing.T, *reconcilertesting.TableRow) {
	apiVersion, kind := gvk.ToAPIVersionAndKind()

	return func(t *testing.T, r *reconcilertesting.TableRow) {
		tracker := r.Ctx.Value(TrackerKey).(*reconcilertesting.FakeTracker)
		refs := tracker.References()

		for _, ref := range refs {
			if ref.APIVersion == apiVersion &&
				ref.Name == name &&
				ref.Namespace == namespace &&
				ref.Kind == kind {
				return
			}
		}

		t.Errorf("Object was not tracked - %s, Name=%s, Namespace=%s", gvk.String(), name, namespace)
	}
}
