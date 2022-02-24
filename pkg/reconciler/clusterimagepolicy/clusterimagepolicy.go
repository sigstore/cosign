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

	"github.com/sigstore/cosign/pkg/apis/cosigned/v1alpha1"
	clusterimagepolicyreconciler "github.com/sigstore/cosign/pkg/client/injection/reconciler/cosigned/v1alpha1/clusterimagepolicy"
	"knative.dev/pkg/reconciler"
	"knative.dev/pkg/tracker"
)

// Reconciler implements clusterimagepolicyreconciler.Interface for
// ClusterImagePolicy resources.
type Reconciler struct {
	// Tracker builds an index of what resources are watching other resources
	// so that we can immediately react to changes tracked resources.
	Tracker tracker.Interface
}

// Check that our Reconciler implements Interface
var _ clusterimagepolicyreconciler.Interface = (*Reconciler)(nil)

// ReconcileKind implements Interface.ReconcileKind.
func (r *Reconciler) ReconcileKind(ctx context.Context, o *v1alpha1.ClusterImagePolicy) reconciler.Event {
	return nil
}
