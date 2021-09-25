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
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/cosign/pkg/oci/walk"
	providers "github.com/sigstore/cosign/pkg/providers/all"
	sigs "github.com/sigstore/cosign/pkg/signature"
	fulcioClient "github.com/sigstore/fulcio/pkg/client"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func ShouldUploadToTlog(ref name.Reference, force bool, url string) (bool, error) {
	// Check whether experimental is on!
	if !options.EnableExperimental() {
		return false, nil
	}
	// We are forcing publishing to the Tlog.
	if force {
		return true, nil
	}

	// Check if the image is public (no auth in Get)
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

type Uploader func(*client.Rekor, []byte) (*models.LogEntryAnon, error)

func UploadToTlog(ctx context.Context, sv *CertSignVerifier, rekorURL string, upload Uploader) (*oci.Bundle, error) {
	var rekorBytes []byte
	// Upload the cert or the public key, depending on what we have
	if sv.Cert != nil {
		rekorBytes = sv.Cert
	} else {
		pemBytes, err := sigs.PublicKeyPem(sv, signatureoptions.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		rekorBytes = pemBytes
	}
	rekorClient, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return Bundle(entry), nil
}

// Sign subcommand for ffcli.
// Deprecated: this will be deleted when the migration from ffcli to cobra is done.
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
		annotations      = sigs.AnnotationsMap{}
		regOpts          options.RegistryOpts
	)
	options.ApplyRegistryFlags(&regOpts, flagset)
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
			_ = flagset
			_ = key
			_ = cert
			_ = upload
			_ = sk
			_ = slot
			_ = payloadPath
			_ = force
			_ = recursive
			_ = fulcioURL
			_ = rekorURL
			_ = idToken
			_ = oidcIssuer
			_ = oidcClientID
			_ = oidcClientSecret
			_ = attachment
			_ = annotations
			_ = regOpts
			panic("this command is now implemented in cobra.")
		},
	}
}

func GetAttachedImageRef(ref name.Reference, attachment string, remoteOpts ...remote.Option) (name.Reference, error) {
	if attachment == "" {
		return ref, nil
	}
	if attachment == "sbom" {
		return ociremote.SBOMTag(ref, ociremote.WithRemoteOptions(remoteOpts...))
	}
	return nil, fmt.Errorf("unknown attachment type %s", attachment)
}

// nolint
func SignCmd(ctx context.Context, ko KeyOpts, regOpts options.RegistryOpts, annotations map[string]interface{},
	imgs []string, certPath string, upload bool, payloadPath string, force bool, recursive bool, attachment string) error {
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	remoteOpts := regOpts.GetRegistryClientOpts(ctx)

	sv, err := SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	dd := cremote.NewDupeDetector(sv)

	var staticPayload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		staticPayload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
		if err != nil {
			return errors.Wrap(err, "payload from file")
		}
	}

	// Set up an ErrDone considerion to return along "success" paths
	var ErrDone error
	if !recursive {
		ErrDone = mutate.ErrSkipChildren
	}

	for _, inputImg := range imgs {
		ref, err := name.ParseReference(inputImg)
		if err != nil {
			return errors.Wrap(err, "parsing reference")
		}
		ref, err = GetAttachedImageRef(ref, attachment, remoteOpts...)
		if err != nil {
			return fmt.Errorf("unable to resolve attachment %s for image %s", attachment, inputImg)
		}

		se, err := ociremote.SignedEntity(ref, regOpts.ClientOpts(ctx)...)
		if err != nil {
			return err
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// Get the digest for this entity in our walk.
			d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
			if err != nil {
				return err
			}
			digest := ref.Context().Digest(d.String())

			// The payload can be specified via a flag to skip generation.
			payload := staticPayload
			if len(payload) == 0 {
				payload, err = (&sigPayload.Cosign{
					Image:       digest,
					Annotations: annotations,
				}).MarshalJSON()
				if err != nil {
					return errors.Wrap(err, "payload")
				}
			}

			signature, err := sv.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
			if err != nil {
				return errors.Wrap(err, "signing")
			}
			b64sig := base64.StdEncoding.EncodeToString(signature)

			if !upload {
				fmt.Println(b64sig)
				return ErrDone
			}

			opts := []static.Option{}
			if sv.Cert != nil {
				opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
			}

			// Check whether we should be uploading to the transparency log
			if uploadTLog, err := ShouldUploadToTlog(digest, force, ko.RekorURL); err != nil {
				return err
			} else if uploadTLog {
				bundle, err := UploadToTlog(ctx, sv, ko.RekorURL, func(r *client.Rekor, b []byte) (*models.LogEntryAnon, error) {
					return cosign.TLogUpload(r, signature, payload, b)
				})
				if err != nil {
					return err
				}
				opts = append(opts, static.WithBundle(bundle))
			}

			// Create the new signature for this entity.
			sig, err := static.NewSignature(payload, b64sig, opts...)
			if err != nil {
				return err
			}

			// Attach the signature to the entity.
			newSE, err := mutate.AttachSignatureToEntity(se, sig, mutate.WithDupeDetector(dd))
			if err != nil {
				return err
			}

			// Publish the signatures associated with this entity
			if err := ociremote.WriteSignatures(digest.Repository, newSE, regOpts.ClientOpts(ctx)...); err != nil {
				return err
			}
			return ErrDone
		}); err != nil {
			return err
		}
	}

	return nil
}

func Bundle(entry *models.LogEntryAnon) *oci.Bundle {
	if entry.Verification == nil {
		return nil
	}
	return &oci.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Payload: oci.BundlePayload{
			Body:           entry.Body,
			IntegratedTime: *entry.IntegratedTime,
			LogIndex:       *entry.LogIndex,
			LogID:          *entry.LogID,
		},
	}
}

func SignerFromKeyOpts(ctx context.Context, certPath string, ko KeyOpts) (*CertSignVerifier, error) {
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
		return &CertSignVerifier{
			Cert:           pemBytes,
			SignerVerifier: sv,
		}, nil

	case ko.KeyRef != "":
		k, err := sigs.SignerVerifierFromKeyRef(ctx, ko.KeyRef, ko.PassFunc)
		if err != nil {
			return nil, errors.Wrap(err, "reading key")
		}

		certSigner := &CertSignVerifier{
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
	k, err := fulcioverifier.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient)
	if err != nil {
		return nil, errors.Wrap(err, "getting key from Fulcio")
	}
	return &CertSignVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

type CertSignVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
}
