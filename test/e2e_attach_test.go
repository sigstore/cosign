// Copyright 2024 The Sigstore Authors.
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

//go:build e2e && cross

package test

import (
	"bytes"
	"context"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
)

type bomArgType int

const (
	stdinBOM bomArgType = iota
	fileBOM
	rawBOM
)

func TestAttachSBOM_bom_flag(t *testing.T) {
	repo, stop := reg(t)
	defer stop()
	td := t.TempDir()
	ctx := context.Background()
	bomData, err := os.ReadFile("./testdata/bom-go-mod.spdx")
	must(err, t)

	testCases := map[string]struct {
		bom         string
		bomType     bomArgType
		expectedErr bool
	}{
		"stdin containing bom": {
			bom:         string(bomData),
			bomType:     stdinBOM,
			expectedErr: false,
		},
		"file containing bom": {
			bom:         string(bomData),
			bomType:     fileBOM,
			expectedErr: false,
		},
		"raw bom as argument": {
			bom:         string(bomData),
			bomType:     rawBOM,
			expectedErr: true,
		},
		"empty bom as argument": {
			bom:         "",
			bomType:     rawBOM,
			expectedErr: true,
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			imgName := path.Join(repo, "sbom-image")
			img, _, cleanup := mkimage(t, imgName)
			var sbomRef string
			restoreStdin := func() {}
			switch {
			case testCase.bomType == fileBOM:
				sbomRef = mkfile(testCase.bom, td, t)
			case testCase.bomType == stdinBOM:
				sbomRef = "-"
				restoreStdin = mockStdin(testCase.bom, td, t)
			default:
				sbomRef = testCase.bom
			}

			out := bytes.Buffer{}
			_, errPl := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{Platform: "darwin/amd64"}, img.Name(), &out)
			if errPl == nil {
				t.Fatalf("Expected error when passing Platform to single arch image")
			}
			_, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, img.Name(), &out)
			if err == nil {
				t.Fatal("Expected error")
			}
			t.Log(out.String())
			out.Reset()

			// Upload it!
			err = attach.SBOMCmd(ctx, options.RegistryOptions{}, options.RegistryExperimentalOptions{}, sbomRef, "spdx", imgName)
			restoreStdin()

			if testCase.expectedErr {
				mustErr(err, t)
			} else {
				sboms, err := download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, imgName, &out)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(out.String())
				if len(sboms) != 1 {
					t.Fatalf("Expected one sbom, got %d", len(sboms))
				}
				want, err := os.ReadFile("./testdata/bom-go-mod.spdx")
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(string(want), sboms[0]); diff != "" {
					t.Errorf("diff: %s", diff)
				}
			}

			cleanup()
		})
	}
}
