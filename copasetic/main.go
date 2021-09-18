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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func main() {
	fs := flag.NewFlagSet("copasetic", flag.ExitOnError)
	rekorURL := fs.String("rekor-url", "https://rekor.sigstore.dev", "[EXPERIMENTAL] address of rekor STL server")
	var regOpts cli.RegistryOpts
	cli.ApplyRegistryFlags(&regOpts, fs)
	flag.Parse()

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

			img, err := remote.Image(ref, regOpts.GetRegistryClientOpts(bctx.Context)...)
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

			img, err := remote.Image(ref, regOpts.GetRegistryClientOpts(bctx.Context)...)
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
			registryOpts := regOpts.GetRegistryClientOpts(bctx.Context)

			sps, err := cosign.FetchSignaturesForImage(bctx.Context, ref, ociremote.WithRemoteOptions(registryOpts...))
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

			pubKey, err := cli.LoadPublicKey(bctx.Context, key)
			if err != nil {
				return nil, err
			}
			ctxOpt := options.WithContext(bctx.Context)
			co := &cosign.CheckOpts{
				SigVerifier:        pubKey,
				VerifyOpts:         []signature.VerifyOption{ctxOpt},
				PKOpts:             []signature.PublicKeyOption{ctxOpt},
				ClaimVerifier:      cosign.SimpleClaimVerifier,
				RootCerts:          fulcio.GetRoots(),
				RegistryClientOpts: regOpts.GetRegistryClientOpts(bctx.Context),
				RekorURL:           *rekorURL,
				SignatureRepo:      sigRepo,
			}
			sps, err := cosign.Verify(bctx.Context, ref, co)
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
		if errors.Is(err, io.EOF) {
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
