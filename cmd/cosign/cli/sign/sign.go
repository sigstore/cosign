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
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ociempty "github.com/sigstore/cosign/pkg/oci/empty"
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
		if strings.ToUpper(tlogConfirmResponse) != "Y" {
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
func SignCmd(ctx context.Context, ko KeyOpts, regOpts options.RegistryOptions, annotations map[string]interface{},
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

	sv, err := SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()
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
		opts, err := regOpts.ClientOpts(ctx)
		if err != nil {
			return errors.Wrap(err, "constructing client options")
		}
		ref, err = GetAttachedImageRef(ref, attachment, opts...)
		if err != nil {
			return fmt.Errorf("unable to resolve attachment %s for image %s", attachment, inputImg)
		}

		if digest, ok := ref.(name.Digest); ok && !recursive {
			se, err := ociempty.SignedImage(ref)
			if err != nil {
				return err
			}
			err = signDigest(ctx, digest, staticPayload, ko, regOpts, annotations, upload, force, dd, sv, se)
			if err != nil {
				return err
			}
			continue
		}

		se, err := ociremote.SignedEntity(ref, opts...)
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

			err = signDigest(ctx, digest, staticPayload, ko, regOpts, annotations, upload, force, dd, sv, se)
			if err != nil {
				return err
			}
			return ErrDone
		}); err != nil {
			return err
		}
	}

	return nil
}

func signDigest(ctx context.Context, digest name.Digest, payload []byte, ko KeyOpts,
	regOpts options.RegistryOptions, annotations map[string]interface{}, upload bool, force bool,
	dd mutate.DupeDetector, sv *CertSignVerifier, se oci.SignedEntity) error {
	var err error
	// The payload can be passed to skip generation.
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
		return nil
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
	walkOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}

	// Publish the signatures associated with this entity
	if err := ociremote.WriteSignatures(digest.Repository, newSE, walkOpts...); err != nil {
		return err
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
		var pemBytes []byte
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: no x509 certificate retrieved from the PIV token")
		} else {
			pemBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPIV)
			if err != nil {
				return nil, err
			}
		}

		return &CertSignVerifier{
			Cert:           pemBytes,
			SignerVerifier: sv,
			close:          sk.Close,
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

	var k *fulcio.Signer

	if ko.InsecureSkipFulcioVerify {
		k, err = fulcio.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient)
		if err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
	} else {
		k, err = fulcioverifier.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient)
		if err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
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
	close func()
}

func (c *CertSignVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}
