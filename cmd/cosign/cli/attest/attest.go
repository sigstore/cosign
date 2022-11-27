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

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
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
type AttestCommand struct {
	options.KeyOpts
	options.RegistryOptions
	CertPath      string
	CertChainPath string
	NoUpload      bool
	PredicatePath string
	PredicateType string
	Replace       bool
	Timeout       time.Duration
	TlogUpload    bool
	TSAServerURL  string
}

// nolint
func (c *AttestCommand) Exec(ctx context.Context, imageRef string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	predicateURI, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return err
	}
	ref, err := name.ParseReference(imageRef, c.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}
	if _, ok := ref.(name.Digest); !ok {
		msg := fmt.Sprintf(ui.TagReferenceMessage, imageRef)
		ui.Warnf(ctx, msg)
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	ociremoteOpts, err := c.RegistryOptions.ClientOpts(ctx)
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

	sv, err := sign.SignerFromKeyOpts(ctx, c.CertPath, c.CertChainPath, c.KeyOpts)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	var predicate io.ReadCloser
	if c.PredicatePath == "-" {
		fmt.Fprintln(os.Stderr, "Using payload from: standard input")
		predicate = os.Stdin
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", c.PredicatePath)
		predicate, err = os.Open(c.PredicatePath)
		if err != nil {
			return err
		}
		defer predicate.Close()
	}

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      c.PredicateType,
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

	if c.NoUpload {
		fmt.Println(string(signedPayload))
		return nil
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}
	if c.KeyOpts.TSAServerURL != "" {
		clientTSA, err := tsaclient.GetTimestampClient(c.KeyOpts.TSAServerURL)
		if err != nil {
			return fmt.Errorf("failed to create TSA client: %w", err)
		}

		// Here we get the response from the timestamped authority server
		responseBytes, err := tsa.GetTimestampedSignature(signedPayload, clientTSA)
		if err != nil {
			return err
		}
		bundle := cbundle.TimestampToRFC3161Timestamp(responseBytes)

		opts = append(opts, static.WithRFC3161Timestamp(bundle))
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": c.PredicateType,
	}
	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	// Check whether we should be uploading to the transparency log
	shouldUpload, err := sign.ShouldUploadToTlog(ctx, c.KeyOpts, digest, c.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}
	if shouldUpload {
		bundle, err := uploadToTlog(ctx, sv, c.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
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

	if c.Replace {
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
