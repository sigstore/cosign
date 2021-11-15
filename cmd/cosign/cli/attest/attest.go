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

package attest

import (
	"bytes"
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

//nolint
func AttestCmd(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions, imageRef string, certPath string,
	noUpload bool, predicatePath string, force bool, predicateType string, replace bool, timeout time.Duration) error {
	// A key file or token is required unless we're in experimental mode!
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	predicateURI, err := options.ParsePredicateType(predicateType)
	if err != nil {
		return err
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	h, _ := v1.NewHash(digest.Identifier())
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest // nolint

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, predicateURI)
	dd := cremote.NewDupeDetector(sv)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if noUpload {
		fmt.Println(string(signedPayload))
		return nil
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	// Check whether we should be uploading to the transparency log
	if uploadTLog, err := sign.ShouldUploadToTlog(digest, force, ko.RekorURL); err != nil {
		return err
	} else if uploadTLog {
		bundle, err := sign.UploadToTlog(ctx, sv, ko.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadInTotoAttestation(r, signedPayload, b, timeout)
		})
		if err != nil {
			return err
		}
		opts = append(opts, static.WithBundle(bundle))
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest, ociremoteOpts...)
	if err != nil {
		return err
	}

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	if replace {
		ro := cremote.NewReplaceOp(predicateURI)
		signOpts = append(signOpts, mutate.WithReplaceOp(ro))
	}

	// Attach the attestation to the entity.
	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}
