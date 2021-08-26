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
	ggcrV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/attestation"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"

	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
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
	)
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

			ko := KeyOpts{
				KeyRef:   *key,
				PassFunc: GetPass,
				Sk:       *sk,
				Slot:     *slot,
				IDToken:  *idToken,
			}
			for _, img := range args {
				if err := AttestCmd(ctx, ko, img, *cert, *upload, *predicatePath, *force, *predicateType); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}
			return nil
		},
	}
}

const (
	IntotoPayloadType = "application/vnd.in-toto+json"
	DssePayloadType   = "application/vnd.dsse.envelope.v1+json"
)

func AttestCmd(ctx context.Context, ko KeyOpts, imageRef string, certPath string,
	upload bool, predicatePath string, force bool, predicateType string) error {

	// A key file or token is required unless we're in experimental mode!
	if EnableExperimental() {
		if nOf(ko.KeyRef, ko.Sk) > 1 {
			return &KeyParseError{}
		}
	} else {
		if !oneOf(ko.KeyRef, ko.Sk) {
			return &KeyParseError{}
		}
	}

	remoteOpts := DefaultRegistryClientOpts(ctx)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	h, err := Digest(ctx, ref)
	if err != nil {
		return err
	}
	repo := ref.Context()
	img := repo.Digest(h.String())

	sv, err := signerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	wrapped := dsse.WrapSigner(sv, IntotoPayloadType)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Path:   predicatePath,
		Type:   predicateType,
		Digest: h.Hex,
		Repo:   repo.String(),
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}
	sig, err := wrapped.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if !upload {
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
		return nil
	}

	sigRepo, err := TargetRepositoryForImage(ref)
	if err != nil {
		return err
	}
	imgHash, err := ggcrV1.NewHash(img.Identifier())
	if err != nil {
		return err
	}
	attRef := cosign.AttachedImageTag(sigRepo, imgHash, cosign.AttestationTagSuffix)

	uo := cremote.UploadOpts{
		Cert:         sv.Cert,
		Chain:        sv.Chain,
		DupeDetector: sv,
		RemoteOpts:   remoteOpts,
		MediaType:    DssePayloadType,
	}

	uploadTLog, err := shouldUploadToTlog(ref, force, ko.RekorURL)
	if err != nil {
		return err
	}

	if uploadTLog {
		var rekorBytes []byte

		// Upload the cert or the public key, depending on what we have
		if sv.Cert != nil {
			rekorBytes = sv.Cert
		} else {
			pemBytes, err := publicKeyPem(sv, options.WithContext(ctx))
			if err != nil {
				return err
			}
			rekorBytes = pemBytes
		}
		rekorClient, err := rekorClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return err
		}
		entry, err := cosign.TLogUploadInTotoAttestation(rekorClient, sig, rekorBytes)
		if err != nil {
			return err
		}
		fmt.Println("tlog entry created with index: ", *entry.LogIndex)

		uo.Bundle = bundle(entry)
		uo.AdditionalAnnotations = parseAnnotations(entry)
	}

	fmt.Fprintln(os.Stderr, "Pushing attestation to:", attRef.String())
	if _, err = cremote.UploadSignature(sig, payload, attRef, uo); err != nil {
		return errors.Wrap(err, "uploading")
	}

	return nil
}
