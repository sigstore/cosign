// Copyright 2021 The Sigstore Authors.
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

package kubernetes

import (
	"reflect"
	"testing"

	"github.com/sigstore/cosign/pkg/cosign"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecret(t *testing.T) {
	keys := &cosign.Keys{
		PrivateBytes: []byte("private"),
		PublicBytes:  []byte("public"),
	}
	name := "secret"
	namespace := "default"
	expect := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"cosign.key":      []byte("private"),
			"cosign.pub":      []byte("public"),
			"cosign.password": nil,
		},
	}
	actual := secret(keys, namespace, name)
	if !reflect.DeepEqual(actual, expect) {
		t.Errorf("secret: %v, want %v", expect, actual)
	}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		desc      string
		ref       string
		name      string
		namespace string
		shouldErr bool
	}{
		{
			desc:      "valid",
			ref:       "default/cosign-secret",
			name:      "cosign-secret",
			namespace: "default",
		}, {
			desc:      "invalid, 1 field",
			ref:       "something",
			shouldErr: true,
		}, {
			desc:      "invalid, more than 2 fields",
			ref:       "yet/another/arg",
			shouldErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			ns, name, err := parseRef(test.ref)
			if (err == nil) == test.shouldErr {
				t.Fatal("unexpected error")
			}
			if test.shouldErr {
				return
			}
			if name != test.name {
				t.Fatalf("unexpected name: got %v expected %v", name, test.name)
			}
			if ns != test.namespace {
				t.Fatalf("unexpected name: got %v expected %v", ns, test.namespace)
			}
		})
	}
}
