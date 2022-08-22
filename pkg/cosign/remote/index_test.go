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

package remote

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestFilesFromFlagList(t *testing.T) {
	tests := []struct {
		name string
		sl   []string
		want []File
	}{{
		name: "empty",
		sl:   []string{},
		want: []File{},
	}, {
		name: "nil",
		sl:   nil,
		want: []File{},
	}, {
		name: "plain",
		sl:   []string{"foo"},
		want: []File{&file{path: "foo"}},
	}, {
		name: "three",
		sl:   []string{"foo", "foo:darwin", "foo:darwin/amd64"},
		want: []File{
			&file{path: "foo"},
			&file{path: "foo", platform: &v1.Platform{
				OS: "darwin",
			}},
			&file{path: "foo", platform: &v1.Platform{
				OS:           "darwin",
				Architecture: "amd64",
			}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilesFromFlagList(tt.sl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fileFromFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileFromFlag(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want File
	}{{
		name: "plain",
		s:    "foo",
		want: &file{path: "foo"},
	}, {
		name: "os",
		s:    "foo:darwin",
		want: &file{path: "foo", platform: &v1.Platform{
			OS: "darwin",
		}},
	}, {
		name: "os amd64",
		s:    "foo:darwin/amd64",
		want: &file{path: "foo", platform: &v1.Platform{
			OS:           "darwin",
			Architecture: "amd64",
		}},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileFromFlag(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fileFromFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUploadFiles(t *testing.T) {
	var (
		expectedRepo = "foo"
		mt           = DefaultMediaTypeGetter
		err          error
	)
	// Set up a fake registry (with NOP logger to avoid spamming test logs).
	nopLog := log.New(ioutil.Discard, "", 0)
	s := httptest.NewServer(registry.New(registry.Logger(nopLog)))
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		image       string
		fs          []File
		annotations map[string]string
		wantErr     bool
	}{{
		name:  "one file",
		image: "one",
		fs: []File{
			&file{path: "testdata/foo"},
		},
		wantErr: false,
	}, {
		name:  "missing file",
		image: "one-missing",
		fs: []File{
			&file{path: "testdata/missing"},
		},
		wantErr: true,
	},
		{
			name:  "two files with platform",
			image: "two-platform",
			fs: []File{
				&file{path: "testdata/foo", platform: &v1.Platform{
					OS:           "darwin",
					Architecture: "amd64",
				}},
				&file{path: "testdata/bar", platform: &v1.Platform{
					OS:           "linux",
					Architecture: "amd64",
				}},
			},
			wantErr: false,
		}, {
			name:  "one file with annotations",
			image: "one-annotations",
			fs: []File{
				&file{path: "testdata/foo"},
			},
			annotations: map[string]string{
				"foo": "bar",
			},
			wantErr: false,
		}, {
			name:  "two files with annotations",
			image: "two-annotations",
			fs: []File{
				&file{path: "testdata/foo", platform: &v1.Platform{
					OS:           "darwin",
					Architecture: "amd64",
				}},
				&file{path: "testdata/bar", platform: &v1.Platform{
					OS:           "linux",
					Architecture: "amd64",
				}},
			},
			annotations: map[string]string{
				"foo": "bar",
				"bar": "baz",
			},
			wantErr: false,
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := name.ParseReference(fmt.Sprintf("%s/%s/%s:latest", u.Host, expectedRepo, tt.image))
			if err != nil {
				t.Fatalf("ParseRef() = %v", err)
			}
			_, err = UploadFiles(ref, tt.fs, tt.annotations, mt)

			if (err != nil) != tt.wantErr {
				t.Errorf("UploadFiles() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(tt.fs) > 1 {
				if !checkIndex(t, ref) {
					t.Errorf("UploadFiles() index = %v", checkIndex(t, ref))
				}
			}

			for _, f := range tt.fs {
				if f.Platform() != nil {
					if !checkPlatform(t, ref, f.Platform()) {
						t.Errorf("UploadFiles() platform = %v was not found", checkPlatform(t, ref, f.Platform()))
					}
				}
			}

			if tt.annotations != nil {
				if !checkAnnotations(t, ref, tt.annotations) {
					t.Errorf("UploadFiles() annotations = %v was not found", checkAnnotations(t, ref, tt.annotations))
				}
			}
		})
	}
}

func checkPlatform(t *testing.T, ref name.Reference, p *v1.Platform) bool {
	t.Helper()
	d, err := remote.Get(ref)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}

	if d.MediaType.IsIndex() {
		// if it is an index recurse into the index
		idx, err := d.ImageIndex()
		if err != nil {
			t.Fatalf("ImageIndex() = %v", err)
		}
		manifest, err := idx.IndexManifest()
		if err != nil {
			t.Fatalf("IndexManifest() = %v", err)
		}
		for _, m := range manifest.Manifests {
			if !m.MediaType.IsImage() {
				return false
			}
			if m.Platform != nil {
				if m.Platform.OS == p.OS && m.Platform.Architecture == p.Architecture {
					return true
				}
			}
		}
		return false
	} else if d.MediaType.IsImage() {
		// if it is an image check the platform
		if d.Platform != nil {
			if d.Platform.OS == p.OS && d.Platform.Architecture == p.Architecture {
				return true
			}
		}
	}
	return false

}

func checkIndex(t *testing.T, ref name.Reference) bool {
	t.Helper()
	d, err := remote.Get(ref)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if d.MediaType.IsIndex() {
		return true
	}
	return false
}

func checkAnnotations(t *testing.T, ref name.Reference, annotations map[string]string) bool {
	t.Helper()
	var found bool
	d, err := remote.Get(ref)
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}

	if d.MediaType.IsIndex() {
		idx, err := remote.Index(ref)
		if err != nil {
			t.Fatalf("Index() = %v", err)
		}
		m, err := idx.IndexManifest()
		if err != nil {
			t.Fatalf("IndexManifest() = %v", err)
		}
		for annotationsKey := range annotations {
			_, ok := m.Annotations[annotationsKey]
			if ok {
				found = true
			}
		}
		return found
	}

	if d.MediaType.IsImage() {
		i, err := remote.Image(ref)
		if err != nil {
			t.Fatalf("Image() = %v", err)
		}
		m, _ := i.Manifest()
		for annotationsKey := range annotations {
			_, ok := m.Annotations[annotationsKey]
			if ok {
				found = true
			}
		}
		return found
	}
	return false
}
