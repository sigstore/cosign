//
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

package static

import (
	"reflect"
	"testing"

	"github.com/sigstore/cosign/internal/oci"
	ctypes "github.com/sigstore/cosign/pkg/types"
)

func TestOptions(t *testing.T) {
	bundle := &oci.Bundle{}

	tests := []struct {
		name string
		opts []Option
		want *options
	}{{
		name: "no options",
		want: &options{
			MediaType:   ctypes.SimpleSigningMediaType,
			Annotations: make(map[string]string),
		},
	}, {
		name: "with media type",
		opts: []Option{WithMediaType("foo")},
		want: &options{
			MediaType:   "foo",
			Annotations: make(map[string]string),
		},
	}, {
		name: "with annotations",
		opts: []Option{WithAnnotations(map[string]string{
			"foo": "bar",
		})},
		want: &options{
			MediaType: ctypes.SimpleSigningMediaType,
			Annotations: map[string]string{
				"foo": "bar",
			},
		},
	}, {
		name: "with cert chain",
		opts: []Option{WithCertChain([]byte("a"), []byte("b"))},
		want: &options{
			MediaType: ctypes.SimpleSigningMediaType,
			Annotations: map[string]string{
				CertificateAnnotationKey: "a",
				ChainAnnotationKey:       "b",
			},
			Cert:  []byte("a"),
			Chain: []byte("b"),
		},
	}, {
		name: "with bundle",
		opts: []Option{WithBundle(bundle)},
		want: &options{
			MediaType: ctypes.SimpleSigningMediaType,
			Annotations: map[string]string{
				BundleAnnotationKey: "{\"SignedEntryTimestamp\":\"\",\"Payload\":{\"body\":null,\"integratedTime\":0,\"logIndex\":0,\"logID\":\"\"}}",
			},
			Bundle: bundle,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := makeOptions(test.opts...)
			if err != nil {
				t.Fatalf("makeOptions() = %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("makeOptions() = %#v, wanted %#v", got, test.want)
			}
		})
	}
}
