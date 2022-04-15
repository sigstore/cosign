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

package v1alpha1

import (
	"context"
	"fmt"
)

// SetDefaults implements apis.Defaultable
func (c *ClusterImagePolicy) SetDefaults(ctx context.Context) {
	c.Spec.SetDefaults(ctx)
}

func (cs *ClusterImagePolicySpec) SetDefaults(ctx context.Context) {
	for i, authority := range cs.Authorities {
		if authority.Name == "" {
			cs.Authorities[i].Name = fmt.Sprintf("authority-%d", i)
		}
	}
}
