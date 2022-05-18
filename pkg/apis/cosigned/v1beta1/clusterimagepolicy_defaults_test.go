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

package v1beta1

import (
	"context"

	"testing"

	"knative.dev/pkg/apis"
)

func TestNameDefaulting(t *testing.T) {
	tests := []struct {
		in        *ClusterImagePolicy
		wantNames []string
	}{
		{in: cipWithNames([]string{""}),
			wantNames: []string{"authority-0"},
		},
		{in: cipWithNames([]string{"", "vuln-scan"}),
			wantNames: []string{"authority-0", "vuln-scan"},
		},
		{in: cipWithNames([]string{"vuln-scan", ""}),
			wantNames: []string{"vuln-scan", "authority-1"},
		},
		{in: cipWithNames([]string{"first", "second"}),
			wantNames: []string{"first", "second"},
		}}
	for _, tc := range tests {
		tc.in.SetDefaults(context.TODO())
		if len(tc.in.Spec.Authorities) != len(tc.wantNames) {
			t.Fatalf("Mismatch number of wantNames: %d vs authorities: %d", len(tc.wantNames), len(tc.in.Spec.Authorities))
		}
		for i, wantName := range tc.wantNames {
			if tc.in.Spec.Authorities[i].Name != wantName {
				t.Errorf("Wanted name: %s got %s", wantName, tc.in.Spec.Authorities[i].Name)
			}
		}
	}
}

func cipWithNames(names []string) *ClusterImagePolicy {
	cip := &ClusterImagePolicy{
		Spec: ClusterImagePolicySpec{},
	}
	for _, name := range names {
		cip.Spec.Authorities = append(cip.Spec.Authorities, Authority{Name: name, Keyless: &KeylessRef{URL: &apis.URL{Host: "tests.example.com"}}})
	}
	return cip
}
