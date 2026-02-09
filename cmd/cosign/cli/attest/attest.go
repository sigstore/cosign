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
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v3/pkg/cosign/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
)

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
	ref, err := signcommon.ParseOCIReference(ctx, imageRef, c.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
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
	if c.RegistryOptions.AllowHTTPRegistry || c.RegistryOptions.AllowInsecure {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithNameOptions(name.Insecure))
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

	bundleOpts := signcommon.CommonBundleOpts{
		Payload:       payload,
		Digest:        digest,
		PredicateType: types.CosignSignPredicateType,
		BundlePath:    c.BundlePath,
		Upload:        !c.NoUpload,
		OCIRemoteOpts: ociremoteOpts,
	}

	if c.SigningConfig != nil {
		_, err := signcommon.WriteNewBundleWithSigningConfig(ctx, c.KeyOpts, c.CertPath, c.CertChainPath, bundleOpts, c.SigningConfig, c.TrustedMaterial)
		return err
	}

	bundleComponents, closeSV, err := signcommon.GetBundleComponents(ctx, c.CertPath, c.CertChainPath, c.KeyOpts, c.NoUpload, c.TlogUpload, payload, digest, c.RekorEntryType)
	if err != nil {
		return fmt.Errorf("getting bundle components: %w", err)
	}
	defer closeSV()

	sv := bundleComponents.SV

	if c.NoUpload && c.BundlePath == "" {
		fmt.Println(string(bundleComponents.SignedPayload))
		return nil
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	if bundleComponents.RFC3161Timestamp != nil {
		opts = append(opts, static.WithRFC3161Timestamp(bundleComponents.RFC3161Timestamp))
	}

	predicateType, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return err
	}

	bundleOpts.PredicateType = predicateType

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	if bundleComponents.RekorEntry != nil {
		opts = append(opts, static.WithBundle(cbundle.EntryToBundle(bundleComponents.RekorEntry)))
	}

	if c.KeyOpts.NewBundleFormat {
		return signcommon.WriteBundle(ctx, sv, bundleComponents.RekorEntry, bundleOpts, bundleComponents.SignedPayload, bundleComponents.SignerBytes, bundleComponents.TimestampBytes)
	}

	// We don't actually need to access the remote entity to attach things to it
	// so we use a placeholder here.
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)

	dd := cremote.NewDupeDetector(sv)
	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
		mutate.WithRecordCreationTimestamp(c.RecordCreationTimestamp),
	}

	if c.Replace {
		ro := cremote.NewReplaceOp(predicateURI)
		signOpts = append(signOpts, mutate.WithReplaceOp(ro))
	}

	sig, err := static.NewAttestation(bundleComponents.SignedPayload, opts...)
	if err != nil {
		return err
	}

	// Attach the attestation to the entity.
	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}
