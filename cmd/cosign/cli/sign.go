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
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

type annotationsMap struct {
	annotations map[string]interface{}
}

func (a *annotationsMap) Set(s string) error {
	if a.annotations == nil {
		a.annotations = map[string]interface{}{}
	}
	kvp := strings.SplitN(s, "=", 2)
	if len(kvp) != 2 {
		return fmt.Errorf("invalid flag: %s, expected key=value", s)
	}

	a.annotations[kvp[0]] = kvp[1]
	return nil
}

func (a *annotationsMap) String() string {
	s := []string{}
	for k, v := range a.annotations {
		s = append(s, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(s, ",")
}

func Sign() *ffcli.Command {
	var (
		flagset     = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key         = flagset.String("key", "", "path to the private key file or KMS URI")
		upload      = flagset.Bool("upload", true, "whether to upload the signature")
		sk          = flagset.Bool("sk", false, "whether to use a hardware security key")
		payloadPath = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
		force       = flagset.Bool("f", false, "skip warnings and confirmations")
		recursive   = flagset.Bool("r", false, "if a multi-arch image is specified, additionally sign each discrete image")
		idToken     = flagset.String("identity-token", "", "[EXPERIMENTAL] identity token to use for certificate from fulcio")
		annotations = annotationsMap{}
	)
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "cosign sign -key <key path>|<kms uri> [-payload <path>] [-a key=value] [-upload=true|false] [-f] [-r] <image uri>",
		ShortHelp:  `Sign the supplied container image.`,
		LongHelp: `Sign the supplied container image.

EXAMPLES
  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign <IMAGE>

  # sign a container image with a local key pair file
  cosign sign -key cosign.key <IMAGE>

  # sign a multi-arch container image AND all referenced, discrete images
  cosign sign -key cosign.key -r <MULTI-ARCH IMAGE>

  # sign a container image and add annotations
  cosign sign -key cosign.key -a key1=value1 -a key2=value2 <IMAGE>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY>/versions/[VERSION] <IMAGE>
  
  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign -key cosign.key legacy-registry.example.com/my/image
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return flag.ErrHelp
			}

			so := SignOpts{
				KeyRef:      *key,
				Annotations: annotations.annotations,
				Pf:          GetPass,
				Sk:          *sk,
				IDToken:     *idToken,
			}
			for _, img := range args {
				if err := SignCmd(ctx, so, img, *upload, *payloadPath, *force, *recursive); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}
			return nil
		},
	}
}

type SignOpts struct {
	Annotations map[string]interface{}
	KeyRef      string
	Sk          bool
	Pf          cosign.PassFunc
	IDToken     string
}

func getTransitiveImages(rootIndex *remote.Descriptor, repo name.Repository, opts ...remote.Option) ([]name.Digest, error) {
	var imgs []name.Digest

	indexDescs := []*remote.Descriptor{rootIndex}

	for len(indexDescs) > 0 {
		indexDesc := indexDescs[len(indexDescs)-1]
		indexDescs = indexDescs[:len(indexDescs)-1]

		idx, err := indexDesc.ImageIndex()
		if err != nil {
			return nil, err
		}
		idxManifest, err := idx.IndexManifest()
		if err != nil {
			return nil, err
		}
		for _, manifest := range idxManifest.Manifests {
			if manifest.MediaType.IsIndex() {
				nextIndexName := repo.Digest(manifest.Digest.String())
				indexDesc, err := remote.Get(nextIndexName, opts...)
				if err != nil {
					return nil, errors.Wrap(err, "getting recursive image index")
				}
				indexDescs = append(indexDescs, indexDesc)

			}
			childImg := repo.Digest(manifest.Digest.String())
			imgs = append(imgs, childImg)
		}
	}

	return imgs, nil
}

func SignCmd(ctx context.Context, so SignOpts,
	imageRef string, upload bool, payloadPath string, force bool, recursive bool) error {

	// A key file or token is required unless we're in experimental mode!
	if EnableExperimental() {
		if nOf(so.KeyRef, so.Sk) > 1 {
			return &KeyParseError{}
		}
	} else {
		if !oneOf(so.KeyRef, so.Sk) {
			return &KeyParseError{}
		}
	}

	remoteAuth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	get, err := remote.Get(ref, remoteAuth)
	if err != nil {
		return errors.Wrap(err, "getting remote image")
	}

	repo := ref.Context()
	img := repo.Digest(get.Digest.String())

	toSign := []name.Digest{img}

	if recursive && get.MediaType.IsIndex() {
		imgs, err := getTransitiveImages(get, repo, remoteAuth)
		if err != nil {
			return err
		}
		toSign = append(toSign, imgs...)
	}

	var signer signature.Signer
	var dupeDetector signature.Verifier
	var cert, chain string
	switch {
	case so.Sk:
		sk, err := pivkey.NewSignerVerifier()
		if err != nil {
			return err
		}
		signer = sk
		dupeDetector = sk
	case so.KeyRef != "":
		k, err := signerVerifierFromKeyRef(ctx, so.KeyRef, so.Pf)
		if err != nil {
			return errors.Wrap(err, "reading key")
		}
		signer = k
		dupeDetector = k
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		k, err := fulcio.NewSigner(ctx, so.IDToken)
		if err != nil {
			return errors.Wrap(err, "getting key from Fulcio")
		}
		signer = k
		cert, chain = k.Cert, k.Chain
	}

	// Check if the image is public (no auth in Get)
	uploadTLog := EnableExperimental()
	if uploadTLog && !force {
		if _, err := remote.Get(ref); err != nil {
			fmt.Print("warning: uploading to the public transparency log for a private image, please confirm [Y/N]: ")

			var tlogConfirmResponse string
			if _, err := fmt.Scanln(&tlogConfirmResponse); err != nil {
				return err
			}
			if tlogConfirmResponse != "Y" {
				fmt.Println("not uploading to transparency log")
				uploadTLog = false
			}
		}
	}

	var rekorBytes []byte
	if uploadTLog {
		// Upload the cert or the public key, depending on what we have
		if cert != "" {
			rekorBytes = []byte(cert)
		} else {
			pemBytes, err := cosign.PublicKeyPem(ctx, signer)
			if err != nil {
				return err
			}
			rekorBytes = pemBytes
		}
	}

	var staticPayload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		staticPayload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
		if err != nil {
			return errors.Wrap(err, "payload from file")
		}
	}

	for len(toSign) > 0 {
		img := toSign[0]
		toSign = toSign[1:]
		// The payload can be specified via a flag to skip generation.
		payload := staticPayload
		if len(payload) == 0 {
			payload, err = (&sigPayload.Cosign{
				Image:       img,
				Annotations: so.Annotations,
			}).MarshalJSON()
			if err != nil {
				return errors.Wrap(err, "payload")
			}
		}

		sig, _, err := signer.Sign(ctx, payload)
		if err != nil {
			return errors.Wrap(err, "signing")
		}

		if !upload {
			fmt.Println(base64.StdEncoding.EncodeToString(sig))
			continue
		}

		// sha256:... -> sha256-...
		sigRef, err := cosign.SignaturesRef(img)
		if err != nil {
			return err
		}

		uo := cremote.UploadOpts{
			Cert:         cert,
			Chain:        chain,
			DupeDetector: dupeDetector,
			RemoteOpts:   []remote.Option{remoteAuth},
		}

		if uploadTLog {
			rekorClient, err := app.GetRekorClient(TlogServer())
			if err != nil {
				return err
			}
			entry, err := cosign.UploadTLog(rekorClient, sig, payload, rekorBytes)
			if err != nil {
				return err
			}
			fmt.Println("tlog entry created with index: ", *entry.LogIndex)

			uo.Bundle = bundle(entry)
			uo.AdditionalAnnotations = annotations(entry)
		}

		fmt.Fprintln(os.Stderr, "Pushing signature to:", sigRef.String())
		if _, err = cremote.UploadSignature(ctx, sig, payload, sigRef, uo); err != nil {
			return errors.Wrap(err, "uploading")
		}
	}

	return nil
}

func bundle(entry *models.LogEntryAnon) *cremote.Bundle {
	if entry.Verification == nil {
		return nil
	}
	return &cremote.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Body:                 entry.Body,
		IntegratedTime:       *entry.IntegratedTime,
		LogIndex:             entry.LogIndex,
		LogID:                *entry.LogID,
	}
}

func annotations(entry *models.LogEntryAnon) map[string]string {
	annts := map[string]string{}
	if bund := bundle(entry); bund != nil {
		contents, _ := json.Marshal(bund)
		annts[cosign.BundleKey] = string(contents)
	}
	return annts
}
