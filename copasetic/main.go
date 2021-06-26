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

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
)

func main() {

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:    "oci.manifest",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			var tag string

			if err := ast.As(a.Value, &tag); err != nil {
				return nil, err
			}

			ref, err := name.ParseReference(tag)
			if err != nil {
				return nil, err
			}

			creds := remote.WithAuthFromKeychain(authn.DefaultKeychain)
			img, err := remote.Image(ref, creds)
			if err != nil {
				return nil, err
			}

			mfst, err := img.RawManifest()
			if err != nil {
				return nil, err
			}

			v, err := ast.ValueFromReader(bytes.NewReader(mfst))
			if err != nil {
				return nil, err
			}

			return ast.NewTerm(v), nil
		},
	)

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:    "oci.file",
			Decl:    types.NewFunction(types.Args(types.S, types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
			var tag, path string

			if err := ast.As(a.Value, &tag); err != nil {
				return nil, err
			} else if err := ast.As(b.Value, &path); err != nil {
				return nil, err
			}

			ref, err := name.ParseReference(tag)
			if err != nil {
				return nil, err
			}

			creds := remote.WithAuthFromKeychain(authn.DefaultKeychain)
			img, err := remote.Image(ref, creds)
			if err != nil {
				return nil, err
			}

			fc, err := findFile(img, path)
			if err != nil {
				return nil, err
			}
			v := ast.String(string(fc))
			return ast.NewTerm(v), nil
		},
	)

	rego.RegisterBuiltin1(
		&rego.Function{
			Name:    "cosign.signatures",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			var tag string

			if err := ast.As(a.Value, &tag); err != nil {
				return nil, err
			}

			ref, err := name.ParseReference(tag)
			if err != nil {
				return nil, err
			}
			sigRepo, err := cli.TargetRepositoryForImage(ref)
			if err != nil {
				return nil, err
			}

			sps, err := cosign.FetchSignaturesForImage(context.Background(), ref, sigRepo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
			if err != nil {
				return nil, err
			}
			b, err := json.Marshal(sps)
			if err != nil {
				return nil, err
			}
			v, err := ast.ValueFromReader(bytes.NewReader(b))
			if err != nil {
				return nil, err
			}
			return ast.NewTerm(v), nil
		},
	)

	rego.RegisterBuiltin2(
		&rego.Function{
			Name:    "cosign.verify",
			Decl:    types.NewFunction(types.Args(types.S, types.S), types.A),
			Memoize: true,
		},
		func(bctx rego.BuiltinContext, tagParam, keyParam *ast.Term) (*ast.Term, error) {
			var tag string
			if err := ast.As(tagParam.Value, &tag); err != nil {
				return nil, err
			}

			var key string
			if err := ast.As(keyParam.Value, &key); err != nil {
				return nil, err
			}

			ref, err := name.ParseReference(tag)
			if err != nil {
				return nil, err
			}
			sigRepo, err := cli.TargetRepositoryForImage(ref)
			if err != nil {
				return nil, err
			}

			pubKey, err := cosign.LoadPublicKey(bctx.Context, key)
			if err != nil {
				return nil, err
			}
			co := &cosign.CheckOpts{
				PubKey:             pubKey,
				Claims:             true,
				Roots:              fulcio.Roots,
				RegistryClientOpts: []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
			}
			sps, err := cosign.Verify(context.Background(), ref, sigRepo, co, cli.TlogServer())
			if err != nil {
				return nil, err
			}

			b, err := json.Marshal(sps)
			if err != nil {
				return nil, err
			}

			v, err := ast.ValueFromReader(bytes.NewReader(b))
			if err != nil {
				return nil, err
			}
			return ast.NewTerm(v), nil
		},
	)

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func findFile(img v1.Image, path string) ([]byte, error) {
	rc := mutate.Extract(img)
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, err
		}

		fp := hdr.Name
		if !filepath.IsAbs(fp) {
			fp = "/" + fp
		}
		if fp == filepath.Clean(path) {
			if hdr.Typeflag == tar.TypeSymlink {
				// Resolve and recurse!
				dst := hdr.Linkname
				if !filepath.IsAbs(hdr.Linkname) {
					dst, _ = filepath.Abs(filepath.Join(filepath.Dir(fp), filepath.Clean(hdr.Linkname)))
				}
				return findFile(img, dst)
			}
			b, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("path %s not found", path)
}
