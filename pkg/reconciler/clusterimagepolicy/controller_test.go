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
	"testing"

	"knative.dev/pkg/configmap"
	rtesting "knative.dev/pkg/reconciler/testing"

	// Fake injection informers
	_ "github.com/sigstore/cosign/pkg/client/injection/informers/policycontroller/v1alpha1/clusterimagepolicy/fake"
	_ "knative.dev/pkg/client/injection/kube/informers/core/v1/configmap/fake"
	_ "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/configmap/fake"
	_ "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret/fake"
	_ "knative.dev/pkg/injection/clients/namespacedkube/informers/factory/fake"
)

func TestNew(t *testing.T) {
	ctx, _ := rtesting.SetupFakeContext(t)

	c := NewController(ctx, &configmap.ManualWatcher{})

	if c == nil {
		t.Fatal("Expected NewController to return a non-nil value")
	}
}
