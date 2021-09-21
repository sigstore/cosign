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

package sget

import (
	"context"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	ociremote "github.com/sigstore/cosign/internal/oci/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

func New(image, key string, out io.Writer) *SecureGet {
	return &SecureGet{
		ImageRef: image,
		KeyRef:   key,
		Out:      out,
	}
}

type SecureGet struct {
	ImageRef string
	KeyRef   string
	Out      io.Writer
}

func (sg *SecureGet) Do(ctx context.Context) error {
	ref, err := name.ParseReference(sg.ImageRef)
	if err != nil {
		return err
	}

	if _, ok := ref.(name.Tag); ok {
		if sg.KeyRef == "" && !options.EnableExperimental() {
			return errors.New("public key must be specified when fetching by tag, you must fetch by digest or supply a public key")
		}
	}

	opts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	co := &cosign.CheckOpts{
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
	}
	if sg.KeyRef != "" {
		pub, err := sigs.LoadPublicKey(ctx, sg.KeyRef)
		if err != nil {
			return err
		}
		co.SigVerifier = pub
	}

	if co.SigVerifier != nil || options.EnableExperimental() {
		co.RootCerts = fulcio.GetRoots()

		sp, bundleVerified, err := cosign.Verify(ctx, ref, co)
		if err != nil {
			return err
		}
		verify.PrintVerificationHeader(sg.ImageRef, co, bundleVerified)
		verify.PrintVerification(sg.ImageRef, sp, "text")
	}

	// TODO(mattmoor): Depending on what this is, use the higher-level stuff.
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	if len(layers) != 1 {
		return errors.New("invalid artifact")
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		return err
	}

	_, err = io.Copy(sg.Out, rc)
	if err != nil {
		return err
	}
	return nil
}
