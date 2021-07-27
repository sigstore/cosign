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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

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
	)
	return &ffcli.Command{
		Name:       "attest",
		ShortUsage: "cosign attest -key <key path>|<kms uri> [-predicate <path>] [-a key=value] [-upload=true|false] [-f] [-r] <image uri>",
		ShortHelp:  `Attest the supplied container image.`,
		LongHelp: `Attest the supplied container image.

EXAMPLES
  # attach an attestation to a container image Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign attest -attestation <FILE> <IMAGE>

  # attach an attestation to a container image with a local key pair file
  cosign attest -attestation <FILE> -key cosign.key <IMAGE>

  # attach an attestation to a container image with a key pair stored in Azure Key Vault
  cosign attest -attestation <FILE> -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # attach an attestation to a container image with a key pair stored in AWS KMS
  cosign attest -attestation <FILE> -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Google Cloud KMS
  cosign attest -attestation <FILE> -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # attach an attestation to a container image with a key pair stored in Hashicorp Vault
  cosign attest -attestation <FILE> -key hashivault://[KEY] <IMAGE>

  # attach an attestation to a container image which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign attest -attestation <FILE> -key cosign.key legacy-registry.example.com/my/image
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
				if err := AttestCmd(ctx, ko, img, *cert, *upload, *predicatePath, *force); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}
			return nil
		},
	}
}

const intotoPayloadType = "application/vnd.in-toto+json"

func AttestCmd(ctx context.Context, ko KeyOpts, imageRef string, certPath string,
	upload bool, predicatePath string, force bool) error {

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
	wrapped := dsse.WrapSigner(sv, intotoPayloadType)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	rawPayload, err := ioutil.ReadFile(filepath.Clean(predicatePath))
	if err != nil {
		return errors.Wrap(err, "payload from file")
	}

	sh := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          "https://in-toto.io/Statement/v0.1",
			PredicateType: "cosign.sigstore.dev/attestation/v1",
			Subject: []in_toto.Subject{
				{
					Name: repo.String(),
					Digest: map[string]string{
						"sha256": h.Hex,
					},
				},
			},
		},
		Predicate: CosignAttestation{
			Data: string(rawPayload),
		},
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
			pemBytes, err := cosign.PublicKeyPem(sv, options.WithContext(ctx))
			if err != nil {
				return err
			}
			rekorBytes = pemBytes
		}
		rekorClient, err := rekorClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return err
		}
		entry, err := cosign.UploadAttestationTLog(rekorClient, sig, rekorBytes)
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

type CosignAttestation struct {
	Data string
}
