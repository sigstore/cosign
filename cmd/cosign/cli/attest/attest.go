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

package attest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/internal/pkg/cosign/payload"
	irekor "github.com/sigstore/cosign/internal/pkg/cosign/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/providers"
	rekPkgClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	icos "github.com/sigstore/cosign/internal/pkg/cosign"
	ifulcio "github.com/sigstore/cosign/internal/pkg/cosign/fulcio"
	sigs "github.com/sigstore/cosign/pkg/signature"
	fulcPkgClient "github.com/sigstore/fulcio/pkg/client"
)

//nolint
func AttestCmd(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions, imageRef string, certPath string,
	noUpload bool, predicatePath string, force bool, predicateType string, replace bool, timeout time.Duration) error {
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

	predicateURI, err := options.ParsePredicateType(predicateType)
	if err != nil {
		return err
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return errors.Wrap(err, "parsing reference")
	}

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}
	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}
	h, _ := v1.NewHash(digest.Identifier())
	// Overwrite "ref" with a digest to avoid a race where we use a tag
	// multiple times, and it potentially points to different things at
	// each access.
	ref = digest // nolint

	attestor, sv, closeFn, err := AttestorFromKeyOpts(ctx, certPath, predicateURI, ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	if closeFn != nil {
		defer closeFn()
	}
	dd := cremote.NewDupeDetector(sv)

	fmt.Fprintln(os.Stderr, "Using payload from:", predicatePath)
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	// Check whether we should be uploading to the transparency log
	if sign.ShouldUploadToTlog(ctx, digest, force, ko.RekorURL) {
		rClient, err := rekPkgClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return err
		}
		attestor = irekor.WrapDSSEAttestor(attestor, rClient)
	}

	ociAtt, _, err := attestor.Attest(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	if noUpload {
		signedPayload, err := ociAtt.Payload()
		if err != nil {
			return err
		}
		fmt.Println(string(signedPayload))
		return nil
	}

	se, err := ociremote.SignedEntity(digest, ociremoteOpts...)
	if err != nil {
		return err
	}

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
	}

	if replace {
		ro := cremote.NewReplaceOp(predicateURI)
		signOpts = append(signOpts, mutate.WithReplaceOp(ro))
	}

	// Attach the attestation to the entity.
	newSE, err := mutate.AttachAttestationToEntity(se, ociAtt, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}

func attestorFromSecurityKey(keySlot, predicateURI string) (attestor icos.Attestor, sv signature.SignerVerifier, closeFn func(), err error) {
	sk, err := pivkey.GetKeyWithSlot(keySlot)
	if err != nil {
		return nil, nil, nil, err
	}
	sv, err = sk.SignerVerifier()
	if err != nil {
		sk.Close()
		return nil, nil, nil, err
	}

	// Handle the -cert flag.
	// With PIV, we assume the certificate is in the same slot on the PIV
	// token as the private key. If it's not there, show a warning to the
	// user.
	certFromPIV, err := sk.Certificate()
	var certPem []byte
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: no x509 certificate retrieved from the PIV token")
	} else {
		certPem, err = cryptoutils.MarshalCertificateToPEM(certFromPIV)
		if err != nil {
			sk.Close()
			return nil, nil, nil, err
		}
	}

	return payload.NewDSSEAttestor(sv, nil, nil, certPem, nil, predicateURI), sv, sk.Close, nil
}

func attestorFromKeyRef(ctx context.Context, certPath, keyRef string, passFunc cosign.PassFunc, predicateURI string) (attestor icos.Attestor, sv signature.SignerVerifier, closeFn func(), err error) {
	k, err := sigs.SignerVerifierFromKeyRef(ctx, keyRef, passFunc)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "reading key")
	}

	var certBytes []byte

	// Handle the -cert flag
	// With PKCS11, we assume the certificate is in the same slot on the PKCS11
	// token as the private key. If it's not there, show a warning to the
	// user.
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		if certFromPKCS11 == nil {
			fmt.Fprintln(os.Stderr, "warning: no x509 certificate retrieved from the PKCS11 token")
		} else {
			certBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, nil, nil, err
			}
		}

		return payload.NewDSSEAttestor(k, nil, nil, certBytes, nil, predicateURI), k, pkcs11Key.Close, nil
	}

	if certPath == "" {
		return payload.NewDSSEAttestor(k, nil, nil, nil, nil, predicateURI), k, nil, nil
	}

	certBytes, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "read certificate")
	}
	// Handle PEM.
	if bytes.HasPrefix(certBytes, []byte("-----")) {
		decoded, _ := pem.Decode(certBytes)
		if decoded.Type != "CERTIFICATE" {
			return nil, nil, nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certPath)
		}
		certBytes = decoded.Bytes
	}
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parse x509 certificate")
	}
	pk, err := k.PublicKey()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "get public key")
	}
	switch kt := parsedCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !kt.Equal(pk) {
			return nil, nil, nil, errors.New("public key in certificate does not match that in the signing key")
		}
	case *rsa.PublicKey:
		if !kt.Equal(pk) {
			return nil, nil, nil, errors.New("public key in certificate does not match that in the signing key")
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %T", parsedCert.PublicKey)
	}
	pemBytes, err := cryptoutils.MarshalCertificateToPEM(parsedCert)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "marshaling certificate to PEM")
	}

	return payload.NewDSSEAttestor(k, nil, nil, pemBytes, nil, predicateURI), k, nil, nil
}

func keylessAttestor(ctx context.Context, predicateURI string, ko sign.KeyOpts) (attestor icos.Attestor, sv signature.SignerVerifier, err error) {
	fulcioServer, err := url.Parse(ko.FulcioURL)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing Fulcio URL")
	}
	fClient := fulcPkgClient.New(fulcioServer)
	tok := ko.IDToken
	if providers.Enabled(ctx) {
		tok, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, nil, errors.Wrap(err, "fetching ambient OIDC credentials")
		}
	}

	var k *fulcio.Signer

	if ko.InsecureSkipFulcioVerify {
		if k, err = fulcio.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient); err != nil {
			return nil, nil, errors.Wrap(err, "getting key from Fulcio")
		}
	} else {
		if k, err = fulcioverifier.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, fClient); err != nil {
			return nil, nil, errors.Wrap(err, "getting key from Fulcio")
		}
	}

	return ifulcio.WrapAttestor(payload.NewDSSEAttestor(k, nil, nil, nil, nil, predicateURI), k.Cert, k.Chain), k, nil
}

func AttestorFromKeyOpts(ctx context.Context, certPath, predicateURI string, ko sign.KeyOpts) (attestor icos.Attestor, sv signature.SignerVerifier, closeFn func(), err error) {
	if ko.Sk {
		return attestorFromSecurityKey(ko.Slot, predicateURI)
	}

	if ko.KeyRef != "" {
		return attestorFromKeyRef(ctx, certPath, ko.KeyRef, ko.PassFunc, predicateURI)
	}

	// Default Keyless!
	fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
	attestor, sv, err = keylessAttestor(ctx, predicateURI, ko)
	return attestor, sv, nil, err
}
