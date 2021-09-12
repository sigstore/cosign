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
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ggcrV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/providers"
	fulcioClient "github.com/sigstore/fulcio/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"

	// These are the ambient OIDC providers to link in.
	_ "github.com/sigstore/cosign/pkg/providers/github"
	_ "github.com/sigstore/cosign/pkg/providers/google"

	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

func shouldUploadToTlog(ref name.Reference, force bool, url string) (bool, error) {
	// Check if the image is public (no auth in Get)
	if !EnableExperimental() {
		return false, nil
	}
	// Experimental is on!
	if force {
		return true, nil
	}

	if _, err := remote.Get(ref); err != nil {
		fmt.Fprintf(os.Stderr, "warning: uploading to the transparency log at %s for a private image, please confirm [Y/N]: ", url)

		var tlogConfirmResponse string
		if _, err := fmt.Scanln(&tlogConfirmResponse); err != nil {
			return false, err
		}
		if tlogConfirmResponse != "Y" {
			fmt.Fprintln(os.Stderr, "not uploading to transparency log")
			return false, nil
		}
	}
	return true, nil
}

func Sign() *ffcli.Command {
	var (
		flagset          = flag.NewFlagSet("cosign sign", flag.ExitOnError)
		key              = flagset.String("key", "", "path to the private key file, KMS URI or Kubernetes Secret")
		cert             = flagset.String("cert", "", "Path to the x509 certificate to include in the Signature")
		upload           = flagset.Bool("upload", true, "whether to upload the signature")
		sk               = flagset.Bool("sk", false, "whether to use a hardware security key")
		slot             = flagset.String("slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
		payloadPath      = flagset.String("payload", "", "path to a payload file to use rather than generating one.")
		force            = flagset.Bool("f", false, "skip warnings and confirmations")
		recursive        = flagset.Bool("r", false, "if a multi-arch image is specified, additionally sign each discrete image")
		fulcioURL        = flagset.String("fulcio-url", fulcioClient.SigstorePublicServerURL, "[EXPERIMENTAL] address of sigstore PKI server")
		rekorURL         = flagset.String("rekor-url", "https://rekor.sigstore.dev", "[EXPERIMENTAL] address of rekor STL server")
		idToken          = flagset.String("identity-token", "", "[EXPERIMENTAL] identity token to use for certificate from fulcio")
		oidcIssuer       = flagset.String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "[EXPERIMENTAL] OIDC provider to be used to issue ID token")
		oidcClientID     = flagset.String("oidc-client-id", "sigstore", "[EXPERIMENTAL] OIDC client ID for application")
		oidcClientSecret = flagset.String("oidc-client-secret", "", "[EXPERIMENTAL] OIDC client secret for application")
		attachment       = flagset.String("attachment", "", "related image attachment to sign (sbom), default none")
		annotations      = annotationsMap{}
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

  # sign a container image with a key pair stored in Azure Key Vault
  cosign sign -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] <IMAGE>

  # sign a container image with a key pair stored in AWS KMS
  cosign sign -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] <IMAGE>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign -key gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]/versions/[VERSION] <IMAGE>

  # sign a container image with a key pair stored in Hashicorp Vault
  cosign sign -key hashivault://[KEY] <IMAGE>

  # sign a container image with a key pair stored in a Kubernetes secret
  cosign sign -key k8s://[NAMESPACE]/[KEY] <IMAGE>

  # sign a container in a registry which does not fully support OCI media types
  COSIGN_DOCKER_MEDIA_TYPES=1 cosign sign -key cosign.key legacy-registry.example.com/my/image
  `,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return flag.ErrHelp
			}
			switch *attachment {
			case "sbom", "":
				break
			default:
				return flag.ErrHelp
			}
			ko := KeyOpts{
				KeyRef:           *key,
				PassFunc:         GetPass,
				Sk:               *sk,
				Slot:             *slot,
				FulcioURL:        *fulcioURL,
				RekorURL:         *rekorURL,
				IDToken:          *idToken,
				OIDCIssuer:       *oidcIssuer,
				OIDCClientID:     *oidcClientID,
				OIDCClientSecret: *oidcClientSecret,
			}
			for _, img := range args {
				if err := SignCmd(ctx, ko, annotations.annotations, img, *cert, *upload, *payloadPath, *force, *recursive, *attachment); err != nil {
					if *attachment == "" {
						return errors.Wrapf(err, "signing %s", img)
					}
					return errors.Wrapf(err, "signing attachement %s for image %s", *attachment, img)
				}
			}
			return nil
		},
	}
}

func getAttachedImageRef(ctx context.Context, imageRef string, attachment string) (string, error) {
	if attachment == "" {
		return imageRef, nil
	}
	if attachment == "sbom" {
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return "", err
		}

		h, err := Digest(ctx, ref)
		if err != nil {
			return "", err
		}

		repo := ref.Context()
		dstRef := cosign.AttachedImageTag(repo, h, cosign.SBOMTagSuffix)
		return dstRef.Name(), nil
	}
	return "", fmt.Errorf("unknown attachment type %s", attachment)
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

func SignCmd(ctx context.Context, ko KeyOpts, annotations map[string]interface{},
	inputImg string, certPath string, upload bool, payloadPath string, force bool, recursive bool, attachment string) error {
	// A key file or token is required unless we're in experimental mode!
	imageRef, err := getAttachedImageRef(ctx, inputImg, attachment)
	if err != nil {
		return fmt.Errorf("unable to resolve attachment %s for image %s", attachment, inputImg)
	}

	if EnableExperimental() {
		if nOf(ko.KeyRef, ko.Sk) > 1 {
			return &KeyParseError{}
		}
	} else {
		if !oneOf(ko.KeyRef, ko.Sk) {
			return &KeyParseError{}
		}
	}

	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}
	get, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return errors.Wrap(err, "getting remote image")
	}

	repo := ref.Context()
	img := repo.Digest(get.Digest.String())

	toSign := []name.Digest{img}

	if recursive && get.MediaType.IsIndex() {
		imgs, err := getTransitiveImages(get, repo, remoteOpts...)
		if err != nil {
			return err
		}
		toSign = append(toSign, imgs...)
	}
	sv, err := signerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
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
				Annotations: annotations,
			}).MarshalJSON()
			if err != nil {
				return errors.Wrap(err, "payload")
			}
		}

		sig, err := sv.SignMessage(bytes.NewReader(payload), options.WithContext(ctx))
		if err != nil {
			return errors.Wrap(err, "signing")
		}

		if !upload {
			fmt.Fprintln(os.Stderr, base64.StdEncoding.EncodeToString(sig))
			continue
		}

		sigRepo, err := TargetRepositoryForImage(ref)
		if err != nil {
			return err
		}
		imgHash, err := ggcrV1.NewHash(img.Identifier())
		if err != nil {
			return err
		}
		sigRef := cosign.AttachedImageTag(sigRepo, imgHash, cosign.SignatureTagSuffix)

		uo := cremote.UploadOpts{
			Cert:         sv.Cert,
			Chain:        sv.Chain,
			DupeDetector: sv,
			RemoteOpts:   remoteOpts,
		}

		// Check if the image is public (no auth in Get)
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
			entry, err := cosign.TLogUpload(rekorClient, sig, payload, rekorBytes)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "tlog entry created with index: ", *entry.LogIndex)

			uo.Bundle = bundle(entry)
			uo.AdditionalAnnotations = parseAnnotations(entry)
		}

		fmt.Fprintln(os.Stderr, "Pushing signature to:", sigRef.String())
		if _, err = cremote.UploadSignature(sig, payload, sigRef, uo); err != nil {
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
		Payload: cremote.BundlePayload{
			Body:           entry.Body,
			IntegratedTime: *entry.IntegratedTime,
			LogIndex:       *entry.LogIndex,
			LogID:          *entry.LogID,
		},
	}
}

func parseAnnotations(entry *models.LogEntryAnon) map[string]string {
	annts := map[string]string{}
	if bund := bundle(entry); bund != nil {
		contents, _ := json.Marshal(bund)
		annts[cosign.BundleKey] = string(contents)
	}
	return annts
}

func signerFromKeyOpts(ctx context.Context, certPath string, ko KeyOpts) (*certSignVerifier, error) {
	switch {
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		defer sk.Close()
		if err != nil {
			return nil, err
		}
		sv, err := sk.SignerVerifier()
		if err != nil {
			return nil, err
		}

		// Handle the -cert flag.
		// With PIV, we assume the certificate is in the same slot on the PIV
		// token as the private key. If it's not there, show a warning to the
		// user.
		certFromPIV, err := sk.Certificate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: no x509 certificate retrieved from the PIV token")
			break
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(certFromPIV)
		if err != nil {
			return nil, err
		}
		return &certSignVerifier{
			Cert:           pemBytes,
			SignerVerifier: sv,
		}, nil

	case ko.KeyRef != "":
		k, err := signerVerifierFromKeyRef(ctx, ko.KeyRef, ko.PassFunc)
		if err != nil {
			return nil, errors.Wrap(err, "reading key")
		}

		certSigner := &certSignVerifier{
			SignerVerifier: k,
		}
		// Handle the -cert flag
		if certPath == "" {
			return certSigner, nil
		}

		certBytes, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, errors.Wrap(err, "read certificate")
		}
		// Handle PEM.
		if bytes.HasPrefix(certBytes, []byte("-----")) {
			decoded, _ := pem.Decode(certBytes)
			if decoded.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certPath)
			}
			certBytes = decoded.Bytes
		}
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, errors.Wrap(err, "parse x509 certificate")
		}
		pk, err := k.PublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "get public key")
		}
		switch kt := parsedCert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			if !kt.Equal(pk) {
				return nil, errors.New("public key in certificate does not match that in the signing key")
			}
		case *rsa.PublicKey:
			if !kt.Equal(pk) {
				return nil, errors.New("public key in certificate does not match that in the signing key")
			}
		default:
			return nil, fmt.Errorf("unsupported key type: %T", parsedCert.PublicKey)
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(parsedCert)
		if err != nil {
			return nil, errors.Wrap(err, "marshaling certificate to PEM")
		}
		certSigner.Cert = pemBytes
		return certSigner, nil
	}
	// Default Keyless!
	fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
	fulcioServer, err := url.Parse(ko.FulcioURL)
	if err != nil {
		return nil, errors.Wrap(err, "parsing Fulcio URL")
	}
	fClient := fulcioClient.New(fulcioServer)
	tok := ko.IDToken
	if providers.Enabled(ctx) {
		tok, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, errors.Wrap(err, "fetching ambient OIDC credentials")
		}
	}
	k, err := fulcio.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient)
	if err != nil {
		return nil, errors.Wrap(err, "getting key from Fulcio")
	}
	return &certSignVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

type certSignVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
}
