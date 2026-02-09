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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	icos "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	ifulcio "github.com/sigstore/cosign/v3/internal/pkg/cosign/fulcio"
	ipayload "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload"
	irekor "github.com/sigstore/cosign/v3/internal/pkg/cosign/rekor"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cremote "github.com/sigstore/cosign/v3/pkg/cosign/remote"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/walk"
	"github.com/sigstore/cosign/v3/pkg/types"
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
				err = signDigestBundle(ctx, digest, ko, signOpts, annotations)
			} else {
				err = signDigest(ctx, digest, staticPayload, ko, signOpts, annotations, se)
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
				err = signDigestBundle(ctx, digest, ko, signOpts, annotations)
			} else {
				err = signDigest(ctx, digest, staticPayload, ko, signOpts, annotations, se)
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

	if ko.SigningConfig != nil {
		_, err := signcommon.WriteNewBundleWithSigningConfig(ctx, ko, signOpts.Cert, signOpts.CertChain, bundleOpts, ko.SigningConfig, ko.TrustedMaterial)
		if err != nil {
			return err
		}
		return nil
	}

	bundleComponents, closeSV, err := signcommon.GetBundleComponents(ctx, signOpts.Cert, signOpts.CertChain, ko, false, signOpts.TlogUpload, payload, digest, "dsse")
	if err != nil {
		return fmt.Errorf("getting bundle components: %w", err)
	}
	defer closeSV()

	return signcommon.WriteBundle(ctx, bundleComponents.SV, bundleComponents.RekorEntry, bundleOpts, bundleComponents.SignedPayload, bundleComponents.SignerBytes, bundleComponents.TimestampBytes)
}

func signDigest(ctx context.Context, digest name.Digest, payload []byte, ko options.KeyOpts, signOpts options.SignOptions,
	annotations map[string]interface{}, se oci.SignedEntity) error {
	var err error
	var payloads [][]byte
	// The payload can be passed to skip generation.
	if len(payload) == 0 {
		identities := signOpts.SignContainerIdentities
		if len(identities) == 0 {
			identities = append(identities, "")
		}
		for _, identity := range identities {
			payload, err = (&sigPayload.Cosign{
				Image:           digest,
				ClaimedIdentity: identity,
				Annotations:     annotations,
			}).MarshalJSON()
			if err != nil {
				return fmt.Errorf("payload: %w", err)
			}
			payloads = append(payloads, payload)
		}
	} else {
		payloads = append(payloads, payload)
	}

	sv, closeSV, err := signcommon.GetSignerVerifier(ctx, signOpts.Cert, signOpts.CertChain, ko)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer closeSV()

	dd := cremote.NewDupeDetector(sv)

	var s icos.Signer
	s = ipayload.NewSigner(sv)
	if sv.Cert != nil {
		s = ifulcio.NewSigner(s, sv.Cert, sv.Chain)
	}

	if ko.TSAServerURL != "" {
		if ko.TSAClientCACert == "" && ko.TSAClientCert == "" { // no mTLS params or custom CA
			s = tsa.NewSigner(s, client.NewTSAClient(ko.TSAServerURL))
		} else {
			s = tsa.NewSigner(s, client.NewTSAClientMTLS(ko.TSAServerURL,
				ko.TSAClientCACert,
				ko.TSAClientCert,
				ko.TSAClientKey,
				ko.TSAServerName,
			))
		}
	}
	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, digest, signOpts.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}
	if shouldUpload {
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		s = irekor.NewSigner(s, rClient)
	}

	ociSigs := make([]oci.Signature, len(payloads))
	b64sigs := make([]string, len(payloads))

	for i, payload := range payloads {
		ociSig, _, err := s.Sign(ctx, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		ociSigs[i] = ociSig

		b64sig, err := ociSig.Base64Signature()
		if err != nil {
			return err
		}
		b64sigs[i] = b64sig
	}

	outputSignature := signOpts.OutputSignature
	if outputSignature != "" {
		// Add digest to suffix to differentiate each image during recursive signing
		if signOpts.Recursive {
			outputSignature = fmt.Sprintf("%s-%s", outputSignature, strings.Replace(digest.DigestStr(), ":", "-", 1))
		}
		if err := os.WriteFile(outputSignature, []byte(strings.Join(b64sigs, "\n")), 0600); err != nil {
			return fmt.Errorf("create signature file: %w", err)
		}
	}
	outputPayload := signOpts.OutputPayload
	if outputPayload != "" {
		// Add digest to suffix to differentiate each image during recursive signing
		if signOpts.Recursive {
			outputPayload = fmt.Sprintf("%s-%s", outputPayload, strings.Replace(digest.DigestStr(), ":", "-", 1))
		}
		if err := os.WriteFile(outputPayload, bytes.Join(payloads, []byte("\n")), 0600); err != nil {
			return fmt.Errorf("create payload file: %w", err)
		}
	}

	if signOpts.OutputCertificate != "" {
		rekorBytes, err := sv.Bytes(ctx)
		if err != nil {
			return fmt.Errorf("create certificate file: %w", err)
		}

		if err := os.WriteFile(signOpts.OutputCertificate, rekorBytes, 0600); err != nil {
			return fmt.Errorf("create certificate file: %w", err)
		}
		// TODO: maybe accept a --b64 flag as well?
		ui.Infof(ctx, "Certificate wrote in the file %s", signOpts.OutputCertificate)
	}

	if ko.BundlePath != "" {
		var contents [][]byte
		for _, ociSig := range ociSigs {
			signedPayload, err := fetchLocalSignedPayload(ociSig)
			if err != nil {
				return fmt.Errorf("failed to fetch signed payload: %w", err)
			}

			content, err := json.Marshal(signedPayload)
			if err != nil {
				return fmt.Errorf("failed to marshal signed payload: %w", err)
			}
			contents = append(contents, content)
		}
		if err := os.WriteFile(ko.BundlePath, bytes.Join(contents, []byte("\n")), 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	}

	if !signOpts.Upload {
		return nil
	}

	// Attach the signature to the entity.
	var newSE oci.SignedEntity
	for _, ociSig := range ociSigs {
		newSE, err = mutate.AttachSignatureToEntity(se, ociSig, mutate.WithDupeDetector(dd), mutate.WithRecordCreationTimestamp(signOpts.RecordCreationTimestamp))
		if err != nil {
			return err
		}
		se = newSE
	}

	// Publish the signatures associated with this entity
	walkOpts, err := signOpts.Registry.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	// Check if we are overriding the signatures repository location
	repo, _ := ociremote.GetEnvTargetRepository()
	if repo.RepositoryStr() == "" {
		ui.Infof(ctx, "Pushing signature to: %s", digest.Repository)
	} else {
		ui.Infof(ctx, "Pushing signature to: %s", repo.RepositoryStr())
	}

	// Publish the signatures associated with this entity (using OCI 1.1+ behavior)
	if signOpts.RegistryExperimental.RegistryReferrersMode == options.RegistryReferrersModeOCI11 {
		return ociremote.WriteSignaturesExperimentalOCI(digest, newSE, walkOpts...)
	}

	// Publish the signatures associated with this entity
	return ociremote.WriteSignatures(digest.Repository, newSE, walkOpts...)
}

func fetchLocalSignedPayload(sig oci.Signature) (*cosign.LocalSignedPayload, error) {
	signedPayload := &cosign.LocalSignedPayload{}
	var err error

	signedPayload.Base64Signature, err = sig.Base64Signature()
	if err != nil {
		return nil, err
	}

	sigCert, err := sig.Cert()
	if err != nil {
		return nil, err
	}
	if sigCert != nil {
		signedPayload.Cert = base64.StdEncoding.EncodeToString(sigCert.Raw)
	} else {
		signedPayload.Cert = ""
	}

	signedPayload.Bundle, err = sig.Bundle()
	if err != nil {
		return nil, err
	}
	return signedPayload, nil
}
