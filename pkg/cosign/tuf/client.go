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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/client"
)

type registryRemoteStore map[string]json.RawMessage

func RegistryRemoteStore(repo string) (client.RemoteStore, error) {
	// Load all the metadata from well-known.tuf
	// Get the well-known.tuf blob from the repository
	ref, err := name.ParseReference(repo + MetadataFile)
	if err != nil {
		return nil, err
	}

	var storeBlob []byte
	storeBlob, err = cremote.GetFile(ref)
	if err != nil {
		return nil, err
	}

	var rawMeta map[string]json.RawMessage
	if err := json.Unmarshal(storeBlob, &rawMeta); err != nil {
		return nil, err
	}

	return registryRemoteStore(rawMeta), nil
}

func (r registryRemoteStore) GetMeta(name string) (io.ReadCloser, int64, error) {
	meta, ok := r[name]
	if !ok {
		return nil, 0, fmt.Errorf("did not find metadata")
	}
	return ioutil.NopCloser(bytes.NewReader(meta)), int64(len(meta)), nil
}

func (r registryRemoteStore) GetTarget(target string) (io.ReadCloser, int64, error) {
	ref, err := name.ParseReference(target)
	if err != nil {
		return nil, 0, err
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, 0, err
	}

	n, err := img.Size()
	if err != nil {
		return nil, 0, err
	}

	payload, err := img.RawManifest()
	if err != nil {
		return nil, 0, err
	}

	return ioutil.NopCloser(bytes.NewReader(payload)), int64(n), nil
}

func Verify(root []byte, image string) error {
	// set up trusted local store
	meta := map[string]json.RawMessage{"root.json": root}
	local := tuf.MemoryStore(meta, nil)
	repo, err := tuf.NewRepo(local)
	if err != nil {
		return err
	}
	// Get root information
	rootKeys, err := repo.RootKeys()
	if err != nil {
		return err
	}
	rootRole, err := GetRootFromStore(&local)
	if err != nil {
		return err
	}
	threshold := rootRole.Roles["root"].Threshold

	// set up remote store from registry
	ref, err := name.ParseReference(image)
	if err != nil {
		return err
	}
	repository := ref.Context().Name()
	remote, err := RegistryRemoteStore(repository)
	if err != nil {
		return err
	}

	// Create client
	c := client.NewClient(local, remote)
	if err := c.Init(rootKeys, threshold); err != nil {
		return err
	}

	// Download
	targets, err := c.Update()
	if err != nil {
		return err
	}

	for name := range targets {
		if name == image {
			fmt.Fprintf(os.Stderr, "Success!\n")
			return nil
		}
	}

	return fmt.Errorf("target was not found")
}
