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

package attach

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type tlogUploadFn func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*bundle.RekorBundle, error) {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return bundle.EntryToBundle(entry), nil
}

func RekorCmd(ctx context.Context, regOpts options.RegistryOptions, rekorURL, sigRef, payloadRef, certRef, certChainRef, imageRef string) error {
	b64SigBytes, err := signatureBytes(sigRef)
	if err != nil {
		return err
	} else if len(b64SigBytes) == 0 {
		return errors.New("empty signature")
	}

	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return err
	}
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest // nolint

	var payload []byte
	if payloadRef == "" {
		payload, err = cosign.ObsoletePayload(ctx, digest)
	} else {
		payload, err = os.ReadFile(filepath.Clean(payloadRef))
	}
	if err != nil {
		return err
	}

	sig, err := static.NewSignature(payload, string(b64SigBytes))
	if err != nil {
		return err
	}

	var cert []byte
	var certChain []byte

	if certRef != "" {
		cert, err = os.ReadFile(filepath.Clean(certRef))
		if err != nil {
			return err
		}
	}

	if certChainRef != "" {
		certChain, err = os.ReadFile(filepath.Clean(certChainRef))
		if err != nil {
			return err
		}
	}

	sv, err := sign.SignerFromKeyOpts(ctx, certRef, certChainRef, options.KeyOpts{})
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	bundle, err := uploadToTlog(ctx, sv, rekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
		checkSum := sha256.New()
		if _, err := checkSum.Write(payload); err != nil {
			return nil, err
		}
		return cosign.TLogUpload(ctx, r, b64SigBytes, checkSum, b)
	})
	if err != nil {
		return err
	}

	recorSig, err := mutate.Signature(sig, mutate.WithCertChain(cert, certChain), mutate.WithBundle(bundle))
	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest, ociremoteOpts...)
	if err != nil {
		return err
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, recorSig)
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, ociremoteOpts...)
}
