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
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
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

type tlogUploadFn func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*cbundle.RekorBundle, error) {
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
	return cbundle.EntryToBundle(entry), nil
}

// nolint
func AttestCmd(ctx context.Context, ko options.KeyOpts, regOpts options.RegistryOptions, imageRef string, certPath string, certChainPath string,
	noUpload bool, predicatePath string, force bool, predicateType string, replace bool, timeout time.Duration, noTlogUpload bool) error {
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
	ref, err := name.ParseReference(imageRef, regOpts.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
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

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, certChainPath, ko)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	var predicate io.ReadCloser
	if predicatePath == "-" {
		fmt.Fprintln(os.Stderr, "Using payload from: standard input")
		predicate = os.Stdin
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
		predicate, err = os.Open(predicatePath)
		if err != nil {
			return err
		}
		defer predicate.Close()
	}

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
		return fmt.Errorf("signing: %w", err)
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
	if sign.ShouldUploadToTlog(ctx, ko, digest, force, noTlogUpload) {
		bundle, err := uploadToTlog(ctx, sv, ko.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadInTotoAttestation(ctx, r, signedPayload, b)
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
