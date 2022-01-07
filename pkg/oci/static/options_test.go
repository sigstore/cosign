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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	ctypes "github.com/sigstore/cosign/pkg/types"
)

func TestOptions(t *testing.T) {
	bundle := &bundle.RekorBundle{}
	timestamp := &oci.Timestamp{}

	tests := []struct {
		name string
		opts []Option
		want *options
	}{{
		name: "no options",
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations:     make(map[string]string),
		},
	}, {
		name: "with layer media type",
		opts: []Option{WithLayerMediaType("foo")},
		want: &options{
			LayerMediaType:  "foo",
			ConfigMediaType: types.OCIConfigJSON,
			Annotations:     make(map[string]string),
		},
	}, {
		name: "with config media type",
		opts: []Option{WithConfigMediaType("bar")},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: "bar",
			Annotations:     make(map[string]string),
		},
	}, {
		name: "with annotations",
		opts: []Option{WithAnnotations(map[string]string{
			"foo": "bar",
		})},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				"foo": "bar",
			},
		},
	}, {
		name: "with cert chain",
		opts: []Option{WithCertChain([]byte("a"), []byte("b"))},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
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
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				BundleAnnotationKey: "{\"SignedEntryTimestamp\":null,\"Payload\":{\"body\":null,\"integratedTime\":0,\"logIndex\":0,\"logID\":\"\"}}",
			},
			Bundle: bundle,
		},
	}, {
		name: "with timestamp",
		opts: []Option{WithTimestamp(timestamp)},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				TimestampAnnotationKey: `{"signatures":null,"signed":{"_type":"","spec_version":"","version":0,"expires":"0001-01-01T00:00:00Z","meta":null}}`,
			},
			Timestamp: timestamp,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := makeOptions(test.opts...)
			if err != nil {
				t.Fatalf("makeOptions() = %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("makeOptions() = %s", cmp.Diff(got, test.want))
			}
		})
	}
}
