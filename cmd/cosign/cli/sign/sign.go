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
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	icos "github.com/sigstore/cosign/internal/pkg/cosign"
	ifulcio "github.com/sigstore/cosign/internal/pkg/cosign/fulcio"
	ipayload "github.com/sigstore/cosign/internal/pkg/cosign/payload"
	irekor "github.com/sigstore/cosign/internal/pkg/cosign/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ociempty "github.com/sigstore/cosign/pkg/oci/empty"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
	providers "github.com/sigstore/cosign/pkg/providers/all"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func ShouldUploadToTlog(ctx context.Context, ref name.Reference, force bool, url string) bool {
	// Check whether experimental is on!
	if !options.EnableExperimental() {
		return false
	}
	// We are forcing publishing to the Tlog.
	if force {
		return true
	}

	// Check if the image is public (no auth in Get)
	if _, err := remote.Get(ref, remote.WithContext(ctx)); err != nil {
		fmt.Fprintf(os.Stderr, "%q appears to be a private repository, please confirm uploading to the transparency log at %q [Y/N]: ", ref.Context().String(), url)

		var tlogConfirmResponse string
		if _, err := fmt.Scanln(&tlogConfirmResponse); err != nil {
			fmt.Fprintf(os.Stderr, "\nWARNING: skipping transparency log upload (use --force to upload from scripts): %v\n", err)
			return false
		}
		if strings.ToUpper(tlogConfirmResponse) != "Y" {
			fmt.Fprintln(os.Stderr, "not uploading to transparency log")
			return false
		}
	}
	return true
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
	imgs []string, certPath string, upload bool, outputSignature, outputCertificate string, payloadPath string, force bool, recursive bool, attachment string) error {
	if options.EnableExperimental() {
		if options.NOf(ko.KeyRef, ko.Sk) > 1 {
			return &options.KeyParseError{}
		}
	} else {
		if !options.OneOf(ko.KeyRef, ko.Sk) {
			return &options.KeyParseError{}
		}
	}

	// TODO: accept a timeout argument and uncomment the block below
	// if timeout != 0 {
	// 	var cancelFn context.CancelFunc
	// 	ctx, cancelFn = context.WithTimeout(ctx, timeout)
	// 	defer cancelFn()
	// }

	sv, err := SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	defer sv.Close()
	dd := cremote.NewDupeDetector(sv)

	var staticPayload []byte
	if payloadPath != "" {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		staticPayload, err = os.ReadFile(filepath.Clean(payloadPath))
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
				return errors.Wrap(err, "accessing image")
			}
			err = signDigest(ctx, digest, staticPayload, ko, regOpts, annotations, upload, outputSignature, outputCertificate, force, dd, sv, se)
			if err != nil {
				return errors.Wrap(err, "signing digest")
			}
			continue
		}

		se, err := ociremote.SignedEntity(ref, opts...)
		if err != nil {
			return errors.Wrap(err, "accessing entity")
		}

		if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
			// Get the digest for this entity in our walk.
			d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
			if err != nil {
				return errors.Wrap(err, "computing digest")
			}
			digest := ref.Context().Digest(d.String())

			err = signDigest(ctx, digest, staticPayload, ko, regOpts, annotations, upload, outputSignature, outputCertificate, force, dd, sv, se)
			if err != nil {
				return errors.Wrap(err, "signing digest")
			}
			return ErrDone
		}); err != nil {
			return errors.Wrap(err, "recursively signing")
		}
	}

	return nil
}

func signDigest(ctx context.Context, digest name.Digest, payload []byte, ko KeyOpts,
	regOpts options.RegistryOptions, annotations map[string]interface{}, upload bool, outputSignature, outputCertificate string, force bool,
	dd mutate.DupeDetector, sv *SignerVerifier, se oci.SignedEntity) error {
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

	var s icos.Signer
	s = ipayload.NewSigner(sv, nil, nil)
	s = ifulcio.NewSigner(s, sv.Cert, sv.Chain)
	if ShouldUploadToTlog(ctx, digest, force, ko.RekorURL) {
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		s = irekor.NewSigner(s, rClient)
	}

	ociSig, _, err := s.Sign(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	b64sig, err := ociSig.Base64Signature()
	if err != nil {
		return err
	}

	if outputSignature != "" {
		out, err := os.Create(outputSignature)
		if err != nil {
			return errors.Wrap(err, "create signature file")
		}
		defer out.Close()

		if _, err := out.Write([]byte(b64sig)); err != nil {
			return errors.Wrap(err, "write signature to file")
		}
	}

	if !upload {
		return nil
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(se, ociSig, mutate.WithDupeDetector(dd))
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	walkOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}

	fmt.Fprintln(os.Stderr, "Pushing signature to:", digest.Repository)

	// Publish the signatures associated with this entity
	if err := ociremote.WriteSignatures(digest.Repository, newSE, walkOpts...); err != nil {
		return err
	}

	if outputCertificate != "" {
		rekorBytes, err := sv.Bytes(ctx)
		if err != nil {
			return err
		}

		if err := os.WriteFile(outputCertificate, rekorBytes, 0600); err != nil {
			return err
		}
		// TODO: maybe accept a --b64 flag as well?
	}

	return nil
}

func signerFromSecurityKey(keySlot string) (*SignerVerifier, error) {
	sk, err := pivkey.GetKeyWithSlot(keySlot)
	if err != nil {
		return nil, err
	}
	sv, err := sk.SignerVerifier()
	if err != nil {
		sk.Close()
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
			sk.Close()
			return nil, err
		}
	}

	return &SignerVerifier{
		Cert:           pemBytes,
		SignerVerifier: sv,
		close:          sk.Close,
	}, nil
}

func signerFromKeyRef(ctx context.Context, certPath, keyRef string, passFunc cosign.PassFunc) (*SignerVerifier, error) {
	k, err := sigs.SignerVerifierFromKeyRef(ctx, keyRef, passFunc)
	if err != nil {
		return nil, errors.Wrap(err, "reading key")
	}

	// Handle the -cert flag
	// With PKCS11, we assume the certificate is in the same slot on the PKCS11
	// token as the private key. If it's not there, show a warning to the
	// user.
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		var pemBytes []byte
		if certFromPKCS11 == nil {
			fmt.Fprintln(os.Stderr, "warning: no x509 certificate retrieved from the PKCS11 token")
		} else {
			pemBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
		}

		return &SignerVerifier{
			Cert:           pemBytes,
			SignerVerifier: k,
			close:          pkcs11Key.Close,
		}, nil
	}
	certSigner := &SignerVerifier{
		SignerVerifier: k,
	}
	if certPath == "" {
		return certSigner, nil
	}

	certBytes, err := os.ReadFile(certPath)
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

func keylessSigner(ctx context.Context, ko KeyOpts) (*SignerVerifier, error) {
	fClient, err := fulcio.NewClient(ko.FulcioURL)
	if err != nil {
		return nil, errors.Wrap(err, "creating Fulcio client")
	}
	tok := ko.IDToken
	if providers.Enabled(ctx) {
		tok, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, errors.Wrap(err, "fetching ambient OIDC credentials")
		}
	}

	var k *fulcio.Signer

	if ko.InsecureSkipFulcioVerify {
		if k, err = fulcio.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient); err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
	} else {
		if k, err = fulcioverifier.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient); err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
	}

	return &SignerVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

func SignerFromKeyOpts(ctx context.Context, certPath string, ko KeyOpts) (*SignerVerifier, error) {
	if ko.Sk {
		return signerFromSecurityKey(ko.Slot)
	}

	if ko.KeyRef != "" {
		return signerFromKeyRef(ctx, certPath, ko.KeyRef, ko.PassFunc)
	}

	// Default Keyless!
	fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
	return keylessSigner(ctx, ko)
}

type SignerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
	close func()
}

func (c *SignerVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}

func (c *SignerVerifier) Bytes(ctx context.Context) ([]byte, error) {
	if c.Cert != nil {
		fmt.Fprintf(os.Stderr, "using ephemeral certificate:\n%s\n", string(c.Cert))
		return c.Cert, nil
	}

	pemBytes, err := sigs.PublicKeyPem(c, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return pemBytes, nil
}
