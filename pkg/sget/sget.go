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

// Deprecated: This package is deprecated and will be removed in a future release.
package sget

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
)

func New(image, key, rekorURL string, out io.Writer) *SecureGet {
	return &SecureGet{
		ImageRef: image,
		KeyRef:   key,
		RekorURL: rekorURL,
		Out:      out,
	}
}

type SecureGet struct {
	ImageRef string
	KeyRef   string
	RekorURL string
	Out      io.Writer
}

func (sg *SecureGet) Do(ctx context.Context) error {
	ref, err := name.ParseReference(sg.ImageRef)
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

	rekorClient, err := rekor.NewClient(sg.RekorURL)
	if err != nil {
		return fmt.Errorf("creating Rekor client: %w", err)
	}
	co.RekorClient = rekorClient

	co.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
	if err != nil {
		return fmt.Errorf("getting Rekor public keys: %w", err)
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
		// NB: There are only 2 kinds of verification right now:
		// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
		// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
		// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
		// was performed so we don't need to use this fragile logic here.
		fulcioVerified := (co.SigVerifier == nil)

		co.RootCerts, err = fulcio.GetRoots()
		if err != nil {
			return fmt.Errorf("getting Fulcio roots: %w", err)
		}
		co.IntermediateCerts, err = fulcio.GetIntermediates()
		if err != nil {
			return fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
		sp, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
		if err != nil {
			return err
		}
		verify.PrintVerificationHeader(ctx, sg.ImageRef, co, bundleVerified, fulcioVerified)
		verify.PrintVerification(ctx, sg.ImageRef, sp, "text")
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
