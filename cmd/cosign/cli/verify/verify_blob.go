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

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	sigs "github.com/sigstore/cosign/pkg/signature"
	rekorClient "github.com/sigstore/rekor/pkg/client"
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
	var err error
	var cert *x509.Certificate

	if !options.OneOf(ko.KeyRef, ko.Sk, certRef) {
		return &options.PubKeyParseError{}
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		pubKey, err = sigs.PublicKeyFromKeyRef(ctx, ko.KeyRef)
		if err != nil {
			return errors.Wrap(err, "loading public key")
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
		pems, err := os.ReadFile(certRef)
		if err != nil {
			return err
		}

		certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(pems))
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return errors.New("no certs found in pem file")
		}
		cert = certs[0]
		pubKey, err = sigstoresigs.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return err
		}
	}

	var b64sig string
	targetSig, err := blob.LoadFileOrURL(sigRef)
	if err != nil {
		if !os.IsNotExist(err) {
			// ignore if file does not exist, it can be a base64 encoded string as well
			return err
		}
		targetSig = []byte(sigRef)
	}

	if isb64(targetSig) {
		b64sig = string(targetSig)
	} else {
		b64sig = base64.StdEncoding.EncodeToString(targetSig)
	}

	var blobBytes []byte
	if blobRef == "-" {
		blobBytes, err = io.ReadAll(os.Stdin)
	} else {
		blobBytes, err = blob.LoadFileOrURL(blobRef)
	}
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(b64sig)
	if err != nil {
		return err
	}
	if err := pubKey.VerifySignature(bytes.NewReader(sig), bytes.NewReader(blobBytes)); err != nil {
		return err
	}

	if cert != nil { // cert
		if err := cosign.TrustedCert(cert, fulcio.GetRoots()); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Certificate is trusted by Fulcio Root CA")
		fmt.Fprintln(os.Stderr, "Email:", cert.EmailAddresses)
	}
	fmt.Fprintln(os.Stderr, "Verified OK")

	if options.EnableExperimental() {
		rekorClient, err := rekorClient.GetRekorClient(ko.RekorURL)
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
		uuid, index, err := cosign.FindTlogEntry(rekorClient, b64sig, blobBytes, pubBytes)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %q index: %d\n", uuid, index)
		return nil
	}

	return nil
}
