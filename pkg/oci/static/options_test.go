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
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
	ctypes "github.com/sigstore/cosign/pkg/types"
)

func TestOptions(t *testing.T) {
	bundle := &cbundle.RekorBundle{}
	rfc3161Timestamp := &cbundle.RFC3161Timestamp{}

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
		name: "with RFC3161 timestamp bundle",
		opts: []Option{WithRFC3161Timestamp(rfc3161Timestamp)},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				RFC3161TimestampAnnotationKey: "{\"SignedRFC3161Timestamp\":null}",
			},
			RFC3161Timestamp: rfc3161Timestamp,
		},
	}, {
		name: "with RFC3161Timestamp and Rekor bundle",
		opts: []Option{WithRFC3161Timestamp(rfc3161Timestamp), WithBundle(bundle)},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				RFC3161TimestampAnnotationKey: "{\"SignedRFC3161Timestamp\":null}",
				BundleAnnotationKey:           "{\"SignedEntryTimestamp\":null,\"Payload\":{\"body\":null,\"integratedTime\":0,\"logIndex\":0,\"logID\":\"\"}}",
			},
			RFC3161Timestamp: rfc3161Timestamp,
			Bundle:           bundle,
		},
	}, {
		name: "with RFC3161Timestamp and Rekor bundle",
		opts: []Option{WithRFC3161Timestamp(rfc3161Timestamp), WithBundle(bundle)},
		want: &options{
			LayerMediaType:  ctypes.SimpleSigningMediaType,
			ConfigMediaType: types.OCIConfigJSON,
			Annotations: map[string]string{
				RFC3161TimestampAnnotationKey: "{\"SignedRFC3161Timestamp\":null}",
				BundleAnnotationKey:           "{\"SignedEntryTimestamp\":null,\"Payload\":{\"body\":null,\"integratedTime\":0,\"logIndex\":0,\"logID\":\"\"}}",
			},
			RFC3161Timestamp: rfc3161Timestamp,
			Bundle:           bundle,
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
