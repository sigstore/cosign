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

package cli

import (
	"bytes"
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func Attest() *ffcli.Command {
	var (
		flagset       = flag.NewFlagSet("cosign attest", flag.ExitOnError)
		key           = flagset.String("key", "", "path to the private key file, KMS URI or Kubernetes Secret")
		cert          = flagset.String("cert", "", "Path to the x509 certificate to include in the Signature")
		upload        = flagset.Bool("upload", true, "whether to upload the signature")
		sk            = flagset.Bool("sk", false, "whether to use a hardware security key")
		slot          = flagset.String("slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
		predicatePath = flagset.String("predicate", "", "path to the predicate file.")
		force         = flagset.Bool("f", false, "skip warnings and confirmations")
		idToken       = flagset.String("identity-token", "", "[EXPERIMENTAL] identity token to use for certificate from fulcio")
		predicateType = flagset.String("type", "custom", "specify predicate type (default: custom) (slsaprovenance|link|spdx)")
		regOpts       options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "attest",
		ShortUsage: "cosign attest -key <key path>|<kms uri> [-predicate <path>] [-a key=value] [-upload=true|false] [-f] [-r] <image uri>",
		ShortHelp:  `Attest the supplied container image.`,
		LongHelp: `Attest the supplied container image.

EXAMPLES
  # attach an attestation to a container image Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest -predicate <FILE> -type <TYPE> <IMAGE>

  # attach an attestation to a container image with a local key pair file
  cosign attest -predicate <FILE> -type <TYPE> -key cosign.key <IMAGE>

  # attach an attestation to a container image with a key pair stored in Azure Key Vault
  cosign attest -predicate <FILE> -type <TYPE> -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # attach an attestation to a container image with a key pair stored in AWS KMS
  cosign attest -predicate <FILE> -type <TYPE> -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Google Cloud KMS
  cosign attest -predicate <FILE> -type <TYPE> -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Hashicorp Vault
  cosign attest -predicate <FILE> -type <TYPE> -key hashivault://[KEY] <IMAGE>

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest -predicate <FILE> -type <TYPE> -key cosign.key legacy-registry.example.com/my/image
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return flag.ErrHelp
			}

			ko := sign.KeyOpts{
				KeyRef:   *key,
				PassFunc: generate.GetPass,
				Sk:       *sk,
				Slot:     *slot,
				IDToken:  *idToken,
			}
			for _, img := range args {
				if err := AttestCmd(ctx, ko, regOpts, img, *cert, *upload, *predicatePath, *force, *predicateType); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}
			return nil
		},
	}
}

const (
	predicateCustom = "custom"
	predicateSlsa   = "slsaprovenance"
	predicateSpdx   = "spdx"
	predicateLink   = "link"
)

var predicateTypeMap = map[string]string{
	predicateCustom: attestation.CosignCustomProvenanceV01,
	predicateSlsa:   in_toto.PredicateSLSAProvenanceV01,
	predicateSpdx:   in_toto.PredicateSPDX,
	predicateLink:   in_toto.PredicateLinkV1,
}

func AttestCmd(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOpts, imageRef string, certPath string,
	upload bool, predicatePath string, force bool, predicateType string) error {
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

	predicateURI, ok := predicateTypeMap[predicateType]
	if !ok {
		return fmt.Errorf("invalid predicate type: %s", predicateType)
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	digest, err := ociremote.ResolveDigest(ref, regOpts.ClientOpts(ctx)...)
	if err != nil {
		return err
	}
	h, _ := v1.NewHash(digest.Identifier())

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	wrapped := dsse.WrapSigner(sv, predicateURI)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Path:   predicatePath,
		Type:   predicateType,
		Digest: h.Hex,
		Repo:   digest.Repository.String(),
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

	if !upload {
		fmt.Println(base64.StdEncoding.EncodeToString(signedPayload))
		return nil
	}

	opts := []static.Option{static.WithMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	// Check whether we should be uploading to the transparency log
	if uploadTLog, err := sign.ShouldUploadToTlog(digest, force, ko.RekorURL); err != nil {
		return err
	} else if uploadTLog {
		bundle, err := sign.UploadToTlog(ctx, sv, ko.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadInTotoAttestation(r, signedPayload, b)
		})
		if err != nil {
			return err
		}
		opts = append(opts, static.WithBundle(bundle))
	}

	attRef, err := ociremote.AttestationTag(digest, regOpts.ClientOpts(ctx)...)
	if err != nil {
		return err
	}

	sig, err := static.NewSignature(signedPayload, "", opts...)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Pushing attestation to:", attRef.String())
	// An attestation represents both the signature and payload. So store the entire thing
	// in the payload field since they can get large
	return cremote.UploadSignature(sig, attRef, cremote.UploadOpts{
		DupeDetector:       cremote.NewDupeDetector(sv),
		RegistryClientOpts: regOpts.GetRegistryClientOpts(ctx),
	})
}
