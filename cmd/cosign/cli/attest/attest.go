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

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	tsaclient "github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
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
)

type tlogUploadFn func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *sign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*models.LogEntryAnon, error) {
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
	return entry, nil
}

// nolint
type AttestCommand struct {
	options.KeyOpts
	options.RegistryOptions
	CertPath                string
	CertChainPath           string
	NoUpload                bool
	PredicatePath           string
	PredicateType           string
	Replace                 bool
	Timeout                 time.Duration
	TlogUpload              bool
	TSAServerURL            string
	RekorEntryType          string
	RecordCreationTimestamp bool
}

// nolint
func (c *AttestCommand) Exec(ctx context.Context, imageRef string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if c.PredicatePath == "" {
		return fmt.Errorf("predicate cannot be empty")
	}

	if c.RekorEntryType != "dsse" && c.RekorEntryType != "intoto" {
		return fmt.Errorf("unknown value for rekor-entry-type")
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

	predicate, err := predicateReader(c.PredicatePath)
	if err != nil {
		return fmt.Errorf("getting predicate reader: %w", err)
	}
	defer predicate.Close()

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
	var timestampBytes []byte
	var tsaPayload []byte
	if c.KeyOpts.TSAServerURL != "" {
		// We need to decide what signature to send to the timestamp authority.
		//
		// Historically, cosign sent `signedPayload`, which is the entire JSON DSSE
		// Envelope. However, when sigstore clients are verifying a bundle they
		// will use the DSSE Sig field, so we choose what signature to send to
		// the timestamp authority based on our output format.
		if c.KeyOpts.NewBundleFormat {
			tsaPayload, err = cosign.GetDSSESigBytes(signedPayload)
			if err != nil {
				return err
			}
		} else {
			tsaPayload = signedPayload
		}
		tc := tsaclient.NewTSAClient(c.KeyOpts.TSAServerURL)
		if c.KeyOpts.TSAClientCert != "" {
			tc = tsaclient.NewTSAClientMTLS(c.KeyOpts.TSAServerURL,
				c.KeyOpts.TSAClientCACert,
				c.KeyOpts.TSAClientCert,
				c.KeyOpts.TSAClientKey,
				c.KeyOpts.TSAServerName,
			)
		}
		timestampBytes, err = tsa.GetTimestampedSignature(tsaPayload, tc)
		if err != nil {
			return err
		}
		bundle := cbundle.TimestampToRFC3161Timestamp(timestampBytes)

		opts = append(opts, static.WithRFC3161Timestamp(bundle))
	}

	predicateType, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return err
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	// Check whether we should be uploading to the transparency log
	shouldUpload, err := sign.ShouldUploadToTlog(ctx, c.KeyOpts, digest, c.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}
	var rekorEntry *models.LogEntryAnon
	if shouldUpload {
		rekorEntry, err = uploadToTlog(ctx, sv, c.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
			if c.RekorEntryType == "intoto" {
				return cosign.TLogUploadInTotoAttestation(ctx, r, signedPayload, b)
			} else {
				return cosign.TLogUploadDSSEEnvelope(ctx, r, signedPayload, b)
			}

		})
		if err != nil {
			return err
		}
		opts = append(opts, static.WithBundle(cbundle.EntryToBundle(rekorEntry)))
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}

	if c.KeyOpts.NewBundleFormat {
		signerBytes, err := sv.Bytes(ctx)
		if err != nil {
			return err
		}
		pubKey, err := sv.PublicKey()
		if err != nil {
			return err
		}
		bundleBytes, err := cbundle.MakeNewBundle(pubKey, rekorEntry, payload, signedPayload, signerBytes, timestampBytes)
		if err != nil {
			return err
		}
		return ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, predicateType, ociremoteOpts...)
	}

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
		mutate.WithRecordCreationTimestamp(c.RecordCreationTimestamp),
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
