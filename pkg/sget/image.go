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
	"github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

func New(key string, out io.Writer, rekorURL string) *SecureGet {
	if rekorURL == "" {
		rekorURL = "https://rekor.sigstore.dev"
	}
	return &SecureGet{
		KeyRef:   key,
		Out:      out,
		RekorURL: rekorURL,
	}
}

type SecureGet struct {
	KeyRef   string
	Out      io.Writer
	RekorURL string
}

func (sg *SecureGet) GetImage(ctx context.Context, imageRef string) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	opts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	co := &cosign.CheckOpts{
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		RegistryClientOpts: []ociremote.Option{ociremote.WithRemoteOptions(opts...)},
	}
	if _, ok := ref.(name.Tag); ok {
		if sg.KeyRef == "" && !options.EnableExperimental() {
			return errors.New("public key must be specified when fetching by tag, you must fetch by digest or supply a public key")
		}
	}
	// Overwrite "ref" with a digest to avoid a race where we verify the tag,
	// and then access the file through the tag.  This has a race where we
	// might download content that isn't what we verified.
	ref, err = ociremote.ResolveDigest(ref, co.RegistryClientOpts...)
	if err != nil {
		return err
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

		sp, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
		if err != nil {
			return err
		}
		verify.PrintVerificationHeader(imageRef, co, bundleVerified)
		verify.PrintVerification(imageRef, sp, "text")
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
	return err
}
