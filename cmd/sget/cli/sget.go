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

package cli

import (
	"context"
	"errors"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
)

func SgetCmd(ctx context.Context, imageRef, keyRef string) (io.ReadCloser, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	if _, ok := ref.(name.Tag); ok {
		if keyRef == "" && !cli.EnableExperimental() {
			return nil, errors.New("public key must be specified when fetching by tag, you must fetch by digest or supply a public key")
		}
	}

	co := &cosign.CheckOpts{
		ClaimVerifier: cosign.SimpleClaimVerifier,
		VerifyBundle:  true,
		RegistryClientOpts: []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithContext(ctx),
		},
	}
	if keyRef != "" {
		pub, err := cli.LoadPublicKey(ctx, keyRef)
		if err != nil {
			return nil, err
		}
		co.SigVerifier = pub
	}

	if co.SigVerifier != nil || cli.EnableExperimental() {
		co.RootCerts = fulcio.GetRoots()
		sigRepo, err := cli.TargetRepositoryForImage(ref)
		if err != nil {
			return nil, err
		}
		co.SignatureRepo = sigRepo

		sp, err := cosign.Verify(ctx, ref, co)
		if err != nil {
			return nil, err
		}
		cli.PrintVerification(imageRef, sp, co, "text")
	}

	img, err := remote.Image(ref, co.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) != 1 {
		return nil, errors.New("invalid artifact")
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		return nil, err
	}
	return rc, nil
}
