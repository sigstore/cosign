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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/go-openapi/runtime"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoresigs "github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// nolint
func VerifyBlobCmd(ctx context.Context, ko sign.KeyOpts, certRef, sigRef, blobRef string) error {
	var pubKey sigstoresigs.Verifier
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) && !options.EnableExperimental() {
		return &options.PubKeyParseError{}
	}

	sig, b64sig, err := signatures(sigRef)
	if err != nil {
		return err
	}

	blobBytes, err := payloadBytes(blobRef)
	if err != nil {
		return err
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
		}
		pkcs11Key, ok := pubKey.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
	case ko.Sk:
		sk, err := pivkey.GetKeyWithSlot(ko.Slot)
		if err != nil {
			return errors.Wrap(err, "opening piv token")
		}
		defer sk.Close()
		pubKey, err = sk.Verifier()
		if err != nil {
			return errors.Wrap(err, "loading public key from token")
		}
	case certRef != "":
		pubKey, err = loadCertFromFileOrURL(certRef)
		if err != nil {
			return err
		}
	case options.EnableExperimental():
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}

		uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, blobBytes)
		if err != nil {
			return err
		}

		if len(uuids) == 0 {
			return errors.New("could not find a tlog entry for provided blob")
		}

		tlogEntry, err := cosign.GetTlogEntry(ctx, rClient, uuids[0])
		if err != nil {
			return err
		}

		certs, err := extractCerts(tlogEntry)
		if err != nil {
			return err
		}
		cert = certs[0]
		pubKey, err = sigstoresigs.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return err
		}
	}

	// verify the signature
	if err := pubKey.VerifySignature(bytes.NewReader([]byte(sig)), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	// verify the cert
	if err := verifyCert(cert); err != nil {
		return err
	}

	// verify the rekor entry
	if err := verifyRekorEntry(ctx, ko, pubKey, cert, b64sig, blobBytes); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Verified OK")
	return nil
}

// signatures returns the raw signature and the base64 encoded signature
func signatures(sigRef string) (string, string, error) {
	var targetSig []byte
	var err error
	switch {
	case sigRef != "":
		targetSig, err = blob.LoadFileOrURL(sigRef)
		if err != nil {
			if !os.IsNotExist(err) {
				// ignore if file does not exist, it can be a base64 encoded string as well
				return "", "", err
			}
			targetSig = []byte(sigRef)
		}
	default:
		return "", "", fmt.Errorf("missing flag '--signature'")
	}

	var sig, b64sig string
	if isb64(targetSig) {
		b64sig = string(targetSig)
		sigBytes, _ := base64.StdEncoding.DecodeString(b64sig)
		sig = string(sigBytes)
	} else {
		sig = string(targetSig)
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}
	return sig, b64sig, nil
}

func payloadBytes(blobRef string) ([]byte, error) {
	var blobBytes []byte
	var err error
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return nil, err
	}
	return blobBytes, nil
}

func verifyCert(cert *x509.Certificate) error {
	if cert == nil {
		return nil
	}
	if err := cosign.TrustedCert(cert, fulcio.GetRoots()); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Certificate is trusted by Fulcio Root CA")
	fmt.Fprintln(os.Stderr, "Email:", cert.EmailAddresses)
	for _, uri := range cert.URIs {
		fmt.Fprintf(os.Stderr, "URI: %s://%s%s\n", uri.Scheme, uri.Host, uri.Path)
	}
	fmt.Fprintln(os.Stderr, "Issuer: ", sigs.CertIssuerExtension(cert))
	return nil
}

func verifyRekorEntry(ctx context.Context, ko sign.KeyOpts, pubKey sigstoresigs.Verifier, cert *x509.Certificate, b64sig string, blobBytes []byte) error {
	if !options.EnableExperimental() {
		return nil
	}
	rekorClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		return err
	}
	var pubBytes []byte
	if pubKey != nil {
		pubBytes, err = sigs.PublicKeyPem(pubKey, signatureoptions.WithContext(ctx))
		if err != nil {
			return err
		}
	}
	if cert != nil {
		pubBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return err
		}
	}
	uuid, index, err := cosign.FindTlogEntry(ctx, rekorClient, b64sig, blobBytes, pubBytes)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %q index: %d\n", uuid, index)
	return nil
}

func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}
