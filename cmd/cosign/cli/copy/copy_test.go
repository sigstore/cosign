// Copyright 2023 the Sigstore Authors.
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

package copy

import (
	"context"
	"reflect"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
)

func TestCopyAttachmentTagPrefix(t *testing.T) {
	ctx := context.Background()

	refOpts := options.ReferenceOptions{
		TagPrefix: "test-tag",
	}

	srcImg := "alpine"
	destImg := "test-alpine"

	err := CopyCmd(ctx, options.RegistryOptions{
		RefOpts: refOpts,
	}, srcImg, destImg, false, true, []string{}, "")
	if err == nil {
		t.Fatal("failed to copy with attachment-tag-prefix")
	}
}

func TestCopyPlatformOpt(t *testing.T) {
	ctx := context.Background()

	srcImg := "alpine"
	destImg := "test-alpine"

	err := CopyCmd(ctx, options.RegistryOptions{}, srcImg, destImg, false, true, []string{}, "linux/amd64")
	if err == nil {
		t.Fatal("failed to copy with platform")
	}
}

func TestParseOnlyOpt(t *testing.T) {
	tests := []struct {
		only         []string
		sigOnly      bool
		expectErr    bool
		expectTagMap []tagMap
	}{
		{
			only:      []string{"bogus"},
			sigOnly:   true,
			expectErr: true,
		},
		{
			only:         []string{},
			sigOnly:      true,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag},
		},
		{
			only:         []string{"sig"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag},
		},
		{
			only:         []string{"sig"},
			sigOnly:      true,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag},
		},
		{
			only:         []string{"sbom"},
			sigOnly:      true,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SBOMTag, ociremote.SignatureTag},
		},
		{
			only:         []string{"att"},
			sigOnly:      true,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.AttestationTag, ociremote.SignatureTag},
		},
		{
			only:         []string{"sbom"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SBOMTag},
		},
		{
			only:         []string{"att"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.AttestationTag},
		},
		{
			only:         []string{"att", "sbom"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.AttestationTag, ociremote.SBOMTag},
		},
		{
			only:         []string{"sig", "sbom"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag, ociremote.SBOMTag},
		},
		{
			only:         []string{"sig", "att"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag, ociremote.AttestationTag},
		},
		{
			only:         []string{"sig", "att", "sbom"},
			sigOnly:      false,
			expectErr:    false,
			expectTagMap: []tagMap{ociremote.SignatureTag, ociremote.AttestationTag, ociremote.SBOMTag},
		},
		{
			only:      []string{"sig", "att", "sbom", "bad"},
			sigOnly:   false,
			expectErr: true,
		},
	}

	for _, test := range tests {
		result, err := parseOnlyOpt(test.only, test.sigOnly)
		if (err != nil) != test.expectErr {
			t.Errorf("unexpected failure from parseOnlyOpt: expectErr=%v, err = %v", test.expectErr, err)
		} else if !compareTagMaps(result, test.expectTagMap) {
			t.Errorf("result tag map did not match expected value: result: %v expected: %v", result, test.expectTagMap)
		}
	}
}

func compareTagMaps(slice1, slice2 []tagMap) bool {
	if len(slice1) != len(slice2) {
		return false // Different lengths can't be equal
	}

	for _, fn1 := range slice1 {
		found := false
		for _, fn2 := range slice2 {
			if reflect.DeepEqual(reflect.ValueOf(fn1), reflect.ValueOf(fn2)) {
				found = true
				break // Found a match, move to the next fn1
			}
		}
		if !found {
			return false // fn1 not found in slice2
		}
	}

	return true // All functions in slice1 found in slice2
}
