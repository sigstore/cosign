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
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v3/pkg/cosign/remote"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/oci/walk"
	"github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
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

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, digest, signOpts.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}

	if ko.SigningConfig == nil {
		ko.SigningConfig, err = signcommon.NewSigningConfigFromKeyOpts(ko, shouldUpload)
		if err != nil {
			return fmt.Errorf("creating signing config: %w", err)
		}
	}

	_, err = signcommon.WriteNewBundleWithSigningConfig(ctx, ko, signOpts.Cert, signOpts.CertChain, bundleOpts, ko.SigningConfig, ko.TrustedMaterial)
	if err != nil {
		return err
	}

	return nil
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

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, digest, signOpts.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}

	if ko.SigningConfig == nil {
		ko.SigningConfig, err = signcommon.NewSigningConfigFromKeyOpts(ko, shouldUpload)
		if err != nil {
			return fmt.Errorf("creating signing config: %w", err)
		}
	}

	keypair, _, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, signOpts.Cert, signOpts.CertChain)
	if err != nil {
		return fmt.Errorf("getting keypair and token: %w", err)
	}

	var tsaClientTransport http.RoundTripper
	if ko.TSAClientCACert != "" || (ko.TSAClientCert != "" && ko.TSAClientKey != "") {
		tsaClientTransport, err = client.GetHTTPTransport(ko.TSAClientCACert, ko.TSAClientCert, ko.TSAClientKey, ko.TSAServerName, 30*time.Second)
		if err != nil {
			return fmt.Errorf("getting TSA client transport: %w", err)
		}
	}
	cbundleOpts := cbundle.SignOptions{TSAClientTransport: tsaClientTransport}

	ociSigs := make([]oci.Signature, len(payloads))
	b64sigs := make([]string, len(payloads))

	var firstCertPem []byte

	for i, payload := range payloads {
		content := &sign.PlainData{
			Data: payload,
		}

		bundleBytes, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, ko.SigningConfig, ko.TrustedMaterial, cbundleOpts)
		if err != nil {
			return fmt.Errorf("signing bundle: %w", err)
		}

		var bundle protobundle.Bundle
		if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
			return fmt.Errorf("unmarshalling bundle: %w", err)
		}

		sigBytes, extractedCerts, rekorEntry, rfc3161Timestamp, err := signcommon.ExtractElementsFromProtoBundle(&bundle)
		if err != nil {
			return fmt.Errorf("extracting elements from bundle: %w", err)
		}

		var certPem, chainPem []byte
		for j, c := range extractedCerts {
			p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.GetRawBytes()})
			if j == 0 {
				certPem = p
				if i == 0 {
					firstCertPem = p
				}
			} else {
				chainPem = append(chainPem, p...)
			}
		}

		b64sig := base64.StdEncoding.EncodeToString(sigBytes)
		b64sigs[i] = b64sig

		var opts []static.Option
		if certPem != nil {
			opts = append(opts, static.WithCertChain(certPem, chainPem))
		}

		if rfc3161Timestamp != nil {
			opts = append(opts, static.WithRFC3161Timestamp(cbundle.TimestampToRFC3161Timestamp(rfc3161Timestamp.GetSignedTimestamp())))
		}

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

		ociSig, err := static.NewSignature(payload, b64sig, opts...)
		if err != nil {
			return fmt.Errorf("creating signature: %w", err)
		}

		ociSigs[i] = ociSig
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
		var outBytes []byte
		if len(firstCertPem) > 0 {
			outBytes = firstCertPem
		} else {
			pubPem, err := keypair.GetPublicKeyPem()
			if err != nil {
				return fmt.Errorf("getting public key pem: %w", err)
			}
			outBytes = []byte(pubPem)
		}

		if err := os.WriteFile(signOpts.OutputCertificate, outBytes, 0600); err != nil {
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

	ddVerifier, err := signature.LoadVerifier(keypair.GetPublicKey(), crypto.SHA256)
	if err != nil {
		return fmt.Errorf("loading verifier: %w", err)
	}
	dd := cremote.NewDupeDetector(ddVerifier)

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
