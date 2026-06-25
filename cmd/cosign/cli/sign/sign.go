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
	"context"
	"fmt"
	"os"
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

		if digest, ok := ref.(name.Digest); ok && !signOpts.Recursive {
			err = signDigestBundle(ctx, digest, ko, signOpts, annotations)
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
			err = signDigestBundle(ctx, digest, ko, signOpts, annotations)
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

func signDigestBundle(ctx context.Context, digest name.Digest, ko options.KeyOpts, signOpts options.SignOptions, annotations map[string]any) error {
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

	payload, err := protojson.Marshal(statement)
	if err != nil {
		return err
	}

	regOpts := signOpts.Registry
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	if regOpts.AllowHTTPRegistry || regOpts.AllowInsecure {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithNameOptions(name.Insecure))
	}

	bundleOpts := signcommon.CommonBundleOpts{
		Payload:       payload,
		Digest:        digest,
		PredicateType: types.CosignSignPredicateType,
		BundlePath:    signOpts.BundlePath,
		Upload:        signOpts.Upload,
		OCIRemoteOpts: ociremoteOpts,
	}

	if ko.SigningConfig == nil {
		ko.SigningConfig = signcommon.NewEmptySigningConfig()
	}

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, digest, len(ko.SigningConfig.RekorLogURLs()) > 0)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}

	if !shouldUpload {
		ko.SigningConfig.WithRekorLogURLs()
	}

	bundleBytes, err := signcommon.NewAttestationBundle(ctx, ko, signOpts.Cert, signOpts.CertChain, bundleOpts, ko.SigningConfig, ko.TrustedMaterial)
	if err != nil {
		return err
	}

	if signOpts.BundlePath != "" {
		if err := os.WriteFile(signOpts.BundlePath, bundleBytes, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", signOpts.BundlePath)
	}

	if signOpts.Upload {
		ui.Infof(ctx, "Pushing signature to: %s", digest.Repository)
		if err := ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, bundleOpts.PredicateType, bundleOpts.OCIRemoteOpts...); err != nil {
			return err
		}
	}

	return nil
}
