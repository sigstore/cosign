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

package sign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/walk"
	"github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	// Loads OIDC providers
	_ "github.com/sigstore/cosign/v3/pkg/providers/all"
)

func GetAttachedImageRef(ref name.Reference, attachment string, opts ...ociremote.Option) (name.Reference, error) {
	if attachment == "" {
		return ref, nil
	}
	if attachment == "sbom" {
		return ociremote.SBOMTag(ref, opts...)
	}
	return nil, fmt.Errorf("unknown attachment type %s", attachment)
}

// nolint
func SignCmd(ctx context.Context, ro *options.RootOptions, ko options.KeyOpts, signOpts options.SignOptions, imgs []string) error {
	if options.NOf(ko.KeyRef, ko.Sk) > 1 {
		return &options.KeyParseError{}
	}

	ctx, cancel := context.WithTimeout(ctx, ro.Timeout)
	defer cancel()

	var staticPayload []byte
	var err error
	if signOpts.PayloadPath != "" {
		ui.Infof(ctx, "Using payload from: %s", signOpts.PayloadPath)
		staticPayload, err = os.ReadFile(filepath.Clean(signOpts.PayloadPath))
		if err != nil {
			return fmt.Errorf("payload from file: %w", err)
		}
	}

	// Set up an ErrDone consideration to return along "success" paths
	var ErrDone error
	if !signOpts.Recursive {
		ErrDone = mutate.ErrSkipChildren
	}
	regOpts := signOpts.Registry
	opts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	am, err := signOpts.AnnotationsMap()
	if err != nil {
		return fmt.Errorf("getting annotations: %w", err)
	}
	annotations := am.Annotations
	for _, inputImg := range imgs {
		ref, err := signcommon.ParseOCIReference(ctx, inputImg, regOpts.NameOptions()...)
		if err != nil {
			return err
		}
		ref, err = GetAttachedImageRef(ref, signOpts.Attachment, opts...)
		if err != nil {
			return fmt.Errorf("unable to resolve attachment %s for image %s", signOpts.Attachment, inputImg)
		}

		if digest, ok := ref.(name.Digest); ok && !signOpts.Recursive {
			se, err := ociremote.SignedEntity(ref, opts...)
			if _, isEntityNotFoundErr := err.(*ociremote.EntityNotFoundError); isEntityNotFoundErr {
				se = ociremote.SignedUnknown(digest)
			} else if err != nil {
				return fmt.Errorf("accessing image: %w", err)
			}
			if signOpts.NewBundleFormat {
				err = signDigestNewBundle(ctx, digest, ko, signOpts, annotations)
			} else {
				err = signDigestLegacyBundle(ctx, digest, staticPayload, ko, signOpts, annotations, se)
			}
			if err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			continue
		}

		se, err := ociremote.SignedEntity(ref, opts...)
		if err != nil {
			return fmt.Errorf("accessing entity: %w", err)
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// Get the digest for this entity in our walk.
			d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
			if err != nil {
				return fmt.Errorf("computing digest: %w", err)
			}
			digest := ref.Context().Digest(d.String())
			if signOpts.NewBundleFormat {
				err = signDigestNewBundle(ctx, digest, ko, signOpts, annotations)
			} else {
				err = signDigestLegacyBundle(ctx, digest, staticPayload, ko, signOpts, annotations, se)
			}
			if err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
			return ErrDone
		}); err != nil {
			return fmt.Errorf("recursively signing: %w", err)
		}
	}

	return nil
}

func signDigestNewBundle(ctx context.Context, digest name.Digest, ko options.KeyOpts, signOpts options.SignOptions, annotations map[string]any) error {
	var err error

	digestParts := strings.Split(digest.DigestStr(), ":")
	if len(digestParts) != 2 {
		return fmt.Errorf("unable to parse digest %s", digest.DigestStr())
	}

	annoStruct, _ := structpb.NewStruct(annotations)
	subject := intotov1.ResourceDescriptor{
		Digest:      map[string]string{digestParts[0]: digestParts[1]},
		Annotations: annoStruct,
	}

	statement := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{&subject},
		PredicateType: types.CosignSignPredicateType,
		Predicate:     &structpb.Struct{},
	}

	p, err := protojson.Marshal(statement)
	if err != nil {
		return fmt.Errorf("marshalling statement: %w", err)
	}

	ociremoteOpts, outputSignature, outputPayload, err := prepareSignContext(ctx, digest, &ko, signOpts)
	if err != nil {
		return err
	}

	ko.NewBundleFormat = true

	bundleOpts := signcommon.CommonBundleOpts{
		Digest:                  digest,
		PredicateType:           types.CosignSignPredicateType,
		BundlePath:              signOpts.BundlePath,
		Upload:                  signOpts.Upload,
		OCIRemoteOpts:           ociremoteOpts,
		OutputSignature:         outputSignature,
		OutputPayload:           outputPayload,
		OutputCertificate:       signOpts.OutputCertificate,
		RecordCreationTimestamp: signOpts.RecordCreationTimestamp,
		UseDSSE:                 true,
	}

	keypair, sv, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, signOpts.Cert, signOpts.CertChain)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}
	defer sv.Close()

	bundleOpts.Payload = p
	bundleBytes, err := signcommon.SignAndUploadNewBundle(ctx, ko, bundleOpts, ko.SigningConfig, ko.TrustedMaterial, keypair, certBytes, idToken)
	if err != nil {
		return err
	}

	if signOpts.OutputSignature != "" {
		var protoBundle protobundle.Bundle
		if err := protojson.Unmarshal(bundleBytes, &protoBundle); err == nil {
			sig, _, _, _, err := signcommon.ExtractElementsFromProtoBundle(&protoBundle)
			if err == nil {
				if err := os.WriteFile(signOpts.OutputSignature, []byte(base64.StdEncoding.EncodeToString(sig)), 0600); err != nil {
					return fmt.Errorf("create signature file: %w", err)
				}
			}
		}
	}
	if signOpts.OutputPayload != "" {
		if err := os.WriteFile(signOpts.OutputPayload, p, 0600); err != nil {
			return fmt.Errorf("create payload file: %w", err)
		}
	}
	if signOpts.BundlePath != "" {
		if err := os.WriteFile(signOpts.BundlePath, bundleBytes, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", signOpts.BundlePath)
	}

	if signOpts.OutputCertificate != "" {
		var protoBundle protobundle.Bundle
		if err := protojson.Unmarshal(bundleBytes, &protoBundle); err == nil {
			_, cert, _, _, err := signcommon.ExtractElementsFromProtoBundle(&protoBundle)
			if err == nil && cert != nil {
				certPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.GetRawBytes(),
				})
				if err := os.WriteFile(signOpts.OutputCertificate, certPEM, 0600); err != nil {
					return fmt.Errorf("create certificate file: %w", err)
				}
				ui.Infof(ctx, "Certificate wrote in the file %s", signOpts.OutputCertificate)
			}
		}
	}

	return nil
}

func signDigestLegacyBundle(ctx context.Context, digest name.Digest, payload []byte, ko options.KeyOpts, signOpts options.SignOptions, annotations map[string]any, se oci.SignedEntity) error {
	var err error

	var payloads [][]byte
	if len(payload) != 0 {
		payloads = append(payloads, payload)
	} else {
		identities := signOpts.SignContainerIdentities
		if len(identities) == 0 {
			identities = append(identities, "")
		}
		for _, identity := range identities {
			p, err := (&sigPayload.Cosign{
				Image:           digest,
				ClaimedIdentity: identity,
				Annotations:     annotations,
			}).MarshalJSON()
			if err != nil {
				return fmt.Errorf("marshalling payload: %w", err)
			}
			payloads = append(payloads, p)
		}
	}

	ociremoteOpts, outputSignature, outputPayload, err := prepareSignContext(ctx, digest, &ko, signOpts)
	if err != nil {
		return err
	}

	ko.NewBundleFormat = false

	bundleOpts := signcommon.CommonBundleOpts{
		Digest:                  digest,
		PredicateType:           types.CosignSignPredicateType,
		BundlePath:              signOpts.BundlePath,
		Upload:                  signOpts.Upload,
		OCIRemoteOpts:           ociremoteOpts,
		OutputSignature:         outputSignature,
		OutputPayload:           outputPayload,
		OutputCertificate:       signOpts.OutputCertificate,
		RecordCreationTimestamp: signOpts.RecordCreationTimestamp,
	}

	var b64Sigs []string
	var allPayloads [][]byte
	var allBundles [][]byte
	var firstBundle []byte

	keypair, sv, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, signOpts.Cert, signOpts.CertChain)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}
	defer sv.Close()

	for _, p := range payloads {
		opts := bundleOpts
		opts.Payload = p
		bundleBytes, err := signcommon.SignAndUploadLegacyBundle(ctx, ko, opts, ko.SigningConfig, ko.TrustedMaterial, se, keypair, sv, certBytes, idToken)
		if err != nil {
			return err
		}
		if firstBundle == nil {
			firstBundle = bundleBytes
		}

		var protoBundle protobundle.Bundle
		if err := protojson.Unmarshal(bundleBytes, &protoBundle); err != nil {
			return fmt.Errorf("unmarshalling bundle: %w", err)
		}
		sig, cert, rekorEntry, _, err := signcommon.ExtractElementsFromProtoBundle(&protoBundle)
		if err != nil {
			return fmt.Errorf("extracting elements: %w", err)
		}

		pubKeyPem, _ := keypair.GetPublicKeyPem()
		block, _ := pem.Decode([]byte(pubKeyPem))
		if block == nil {
			return fmt.Errorf("decoding public key")
		}

		legacyBytes, err := signcommon.NewLegacyBundleFromProtoBundleElements(sig, cert, block.Bytes, rekorEntry)
		if err != nil {
			return fmt.Errorf("creating legacy bundle: %w", err)
		}
		allBundles = append(allBundles, legacyBytes)
		allPayloads = append(allPayloads, p)

		b64Sigs = append(b64Sigs, base64.StdEncoding.EncodeToString(sig))
	}

	if outputSignature != "" {
		if err := os.WriteFile(outputSignature, []byte(strings.Join(b64Sigs, "\n")), 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
	}
	if outputPayload != "" {
		if err := os.WriteFile(outputPayload, bytes.Join(allPayloads, []byte("\n")), 0600); err != nil {
			return fmt.Errorf("create payload file: %w", err)
		}
	}
	if signOpts.BundlePath != "" {
		if err := os.WriteFile(signOpts.BundlePath, bytes.Join(allBundles, []byte("\n")), 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", signOpts.BundlePath)
	}

	if signOpts.OutputCertificate != "" && firstBundle != nil {
		var protoBundle protobundle.Bundle
		if err := protojson.Unmarshal(firstBundle, &protoBundle); err != nil {
			return nil // ignore if unmarshal fails as this is certificate only
		}
		_, cert, _, _, err := signcommon.ExtractElementsFromProtoBundle(&protoBundle)
		if err == nil && cert != nil {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.GetRawBytes(),
			})
			if err := os.WriteFile(signOpts.OutputCertificate, certPEM, 0600); err != nil {
				return fmt.Errorf("create certificate file: %w", err)
			}
			ui.Infof(ctx, "Certificate wrote in the file %s", signOpts.OutputCertificate)
		}
	}

	return nil
}

func prepareSignContext(ctx context.Context, digest name.Digest, ko *options.KeyOpts, signOpts options.SignOptions) (ociremoteOpts []ociremote.Option, outputSignature, outputPayload string, err error) {
	regOpts := signOpts.Registry
	ociremoteOpts, err = regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("constructing client options: %w", err)
	}
	if regOpts.AllowHTTPRegistry || regOpts.AllowInsecure {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithNameOptions(name.Insecure))
	}

	outputSignature = signOpts.OutputSignature
	outputPayload = signOpts.OutputPayload
	if signOpts.Recursive {
		// Add digest to suffix to differentiate each image during recursive signing
		suffix := strings.Replace(digest.DigestStr(), ":", "-", 1)
		if outputSignature != "" {
			outputSignature = fmt.Sprintf("%s-%s", outputSignature, suffix)
		}
		if outputPayload != "" {
			outputPayload = fmt.Sprintf("%s-%s", outputPayload, suffix)
		}
	}

	if ko.SigningConfig == nil {
		ko.SigningConfig, err = signcommon.NewSigningConfigFromKeyOpts(*ko, signOpts.TlogUpload)
		if err != nil {
			return nil, "", "", fmt.Errorf("creating signing config: %w", err)
		}
	}

	return ociremoteOpts, outputSignature, outputPayload, nil
}
