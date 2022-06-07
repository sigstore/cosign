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

package tuf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/theupdateframework/go-tuf/client"
)

// This is a partial validation.
// Full bucket naming rules here: https://cloud.google.com/storage/docs/naming-buckets
var bucketRE = regexp.MustCompile("^[a-z0-9][a-z0-9-_.]{1,61}[a-z0-9]$")

type GcsRemoteOptions struct {
	MetadataPath string
	TargetsPath  string
}

type gcsRemoteStore struct {
	bucket string
	ctx    context.Context
	opts   *GcsRemoteOptions
}

func validBucketName(b string) bool {
	if !bucketRE.MatchString(b) {
		return false
	}
	if strings.HasPrefix(b, "goog") {
		return false
	}
	if strings.Contains(b, "google") {
		return false
	}
	return true
}

// GCSRemoteStore is a remote store for TUF metadata on GCS.
func GCSRemoteStore(ctx context.Context, bucket string, opts *GcsRemoteOptions) (client.RemoteStore, error) {
	if opts == nil {
		opts = &GcsRemoteOptions{}
	}
	if opts.TargetsPath == "" {
		opts.TargetsPath = "targets"
	}
	if !validBucketName(bucket) {
		return nil, fmt.Errorf("bucket name %q is invalid", bucket)
	}
	return &gcsRemoteStore{ctx: ctx, bucket: bucket, opts: opts}, nil
}

func (h *gcsRemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	return h.get(path.Clean(path.Join(h.opts.MetadataPath, name)))
}

func (h *gcsRemoteStore) GetTarget(name string) (io.ReadCloser, int64, error) {
	return h.get(path.Clean(path.Join(h.opts.TargetsPath, name)))
}

func (h *gcsRemoteStore) get(path string) (io.ReadCloser, int64, error) {
	url := fmt.Sprintf("https://%s.storage.googleapis.com/%s", h.bucket, path)
	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, client.ErrNotFound{File: path}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, resp.ContentLength, nil
	case http.StatusNotFound:
		return nil, 0, client.ErrNotFound{File: path}
	default:
		defer resp.Body.Close()
		all, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("GET %q: %s", url, string(all))
	}
}
