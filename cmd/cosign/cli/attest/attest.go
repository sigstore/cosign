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
	"crypto"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v3/pkg/cosign/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
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
		PredicateType: predicateURI,
		BundlePath:    c.BundlePath,
		Upload:        !c.NoUpload,
		OCIRemoteOpts: ociremoteOpts,
	}

	if c.SigningConfig == nil {
		c.SigningConfig, err = signcommon.NewSigningConfigFromKeyOpts(c.KeyOpts, c.TlogUpload)
		if err != nil {
			return fmt.Errorf("creating signing config: %w", err)
		}
	}

	bundleBytes, keypair, err := signcommon.NewBundleWithSigningConfig(ctx, c.KeyOpts, c.CertPath, c.CertChainPath, bundleOpts, c.SigningConfig, c.TrustedMaterial)
	if err != nil {
		return fmt.Errorf("creating bundle: %w", err)
	}

	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return fmt.Errorf("unmarshalling bundle: %w", err)
	}

	sig, extractedCerts, rekorEntry, rfc3161Timestamp, err := signcommon.ExtractElementsFromProtoBundle(&bundle)
	if err != nil {
		return fmt.Errorf("extracting elements from bundle: %w", err)
	}

	var legacyBundleBytes []byte
	if !c.NewBundleFormat {
		pubKeyPem, err := keypair.GetPublicKeyPem()
		if err != nil {
			return fmt.Errorf("getting public key: %w", err)
		}
		block, _ := pem.Decode([]byte(pubKeyPem))
		if block == nil {
			return fmt.Errorf("failed to decode public key pem")
		}
		var leafCert *pb_go_v1.X509Certificate
		if len(extractedCerts) > 0 {
			leafCert = extractedCerts[0]
		}
		legacyBundleBytes, err = signcommon.NewLegacyBundleFromProtoBundleElements(sig, leafCert, block.Bytes, rekorEntry)
		if err != nil {
			return fmt.Errorf("creating legacy bundle: %w", err)
		}
	}

	if c.BundlePath != "" {
		var contents []byte
		if c.NewBundleFormat {
			contents = bundleBytes
		} else {
			contents = legacyBundleBytes
		}

		if err := os.WriteFile(c.BundlePath, contents, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", c.BundlePath)
	}

	if !c.NoUpload {
		if c.NewBundleFormat {
			if err := ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, bundleOpts.PredicateType, ociremoteOpts...); err != nil {
				return fmt.Errorf("writing bundle: %w", err)
			}
			return nil
		} else {
			var certPem, chainPem []byte
			for i, c := range extractedCerts {
				p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.GetRawBytes()})
				if i == 0 {
					certPem = p
				} else {
					chainPem = append(chainPem, p...)
				}
			}

			opts := []static.Option{
				static.WithLayerMediaType(types.DssePayloadType),
				static.WithAnnotations(map[string]string{
					"predicateType": predicateURI,
				}),
			}
			if certPem != nil {
				opts = append(opts, static.WithCertChain(certPem, chainPem))
			}

			if rfc3161Timestamp != nil {
				opts = append(opts, static.WithRFC3161Timestamp(cbundle.TimestampToRFC3161Timestamp(rfc3161Timestamp.GetSignedTimestamp())))
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

			if rekorEntry != nil {
				rb := &cbundle.RekorBundle{
					SignedEntryTimestamp: rekorEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
					Payload: cbundle.RekorPayload{
						Body:           rekorEntry.GetCanonicalizedBody(),
						IntegratedTime: rekorEntry.GetIntegratedTime(),
						LogIndex:       rekorEntry.GetLogIndex(),
						LogID:          hex.EncodeToString(rekorEntry.GetLogId().GetKeyId()),
					},
				}
				opts = append(opts, static.WithBundle(rb))
			}

			ociSig, err := static.NewAttestation(sig, opts...)
			if err != nil {
				return fmt.Errorf("creating attestation: %w", err)
			}

			// We don't actually need to access the remote entity to attach things to it
			// so we use a placeholder here.
			se := ociremote.SignedUnknown(digest, ociremoteOpts...)

			ddVerifier, err := signature.LoadVerifier(keypair.GetPublicKey(), crypto.SHA256)
			if err != nil {
				return fmt.Errorf("loading verifier: %w", err)
			}
			dd := cremote.NewDupeDetector(ddVerifier)
			signOpts := []mutate.SignOption{
				mutate.WithDupeDetector(dd),
				mutate.WithRecordCreationTimestamp(c.RecordCreationTimestamp),
			}

			if c.Replace {
				ro := cremote.NewReplaceOp(predicateURI)
				signOpts = append(signOpts, mutate.WithReplaceOp(ro))
			}

			// Attach the attestation to the entity.
			newSE, err := mutate.AttachAttestationToEntity(se, ociSig, signOpts...)
			if err != nil {
				return fmt.Errorf("attaching attestation: %w", err)
			}

			// Publish the attestations associated with this entity
			return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
		}
	} else {
		if c.BundlePath == "" {
			fmt.Println(string(sig))
		}
		return nil
	}
}
