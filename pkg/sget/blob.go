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

package sget

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/go-openapi/runtime"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/blob"
	"github.com/sigstore/cosign/pkg/cosign"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoresigs "github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func (sg *SecureGet) GetBlob(ctx context.Context, sigRef, artifactRef string) error {
	var pubKey sigstoresigs.Verifier
	var err error
	var cert *x509.Certificate

	artifact, err := blob.LoadFileOrURL(artifactRef)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		artifact = []byte(artifactRef)
	}

	if sigRef == "" {
		sigRef = artifactRef + ".sig"
	}

	targetSig, err := blob.LoadFileOrURL(sigRef)
	if err != nil {
		if !os.IsNotExist(err) {
			// ignore if file does not exist, it can be a base64 encoded string as well
			return err
		}
		targetSig = []byte(sigRef)
	}

	if isb64(targetSig) {
		targetSig, err = base64.StdEncoding.DecodeString(string(targetSig))
		if err != nil {
			return err
		}
	}

	rClient, err := rekor.NewClient(sg.RekorURL)
	if err != nil {
		return err
	}

	uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, artifact)
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

	if err := pubKey.VerifySignature(bytes.NewReader(targetSig), bytes.NewReader(artifact)); err != nil {
		return err
	}

	if cert != nil { // cert
		if err := cosign.TrustedCert(cert, fulcio.GetRoots()); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Certificate is trusted by Fulcio Root CA")
		fmt.Fprintln(os.Stderr, "Email:", cert.EmailAddresses)
		for _, uri := range cert.URIs {
			fmt.Fprintf(os.Stderr, "URI: %s://%s%s\n", uri.Scheme, uri.Host, uri.Path)
		}
		fmt.Fprintln(os.Stderr, "Issuer: ", sigs.CertIssuerExtension(cert))
	}
	fmt.Fprintln(os.Stderr, "Verified OK")

	rekorClient, err := rekor.NewClient(sg.RekorURL)
	if err != nil {
		return err
	}
	var pubBytes []byte

	pubBytes, err = sigs.PublicKeyPem(pubKey, signatureoptions.WithContext(ctx))
	if err != nil {
		return err
	}

	if cert != nil {
		pubBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return err
		}
	}

	b64sig := base64.StdEncoding.EncodeToString(targetSig)
	if err != nil {
		return err
	}

	uuid, index, err := cosign.FindTlogEntry(ctx, rekorClient, b64sig, artifact, pubBytes)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "tlog entry verified with uuid: %q index: %d\n", uuid, index)

	_, err = sg.Out.Write(artifact)
	if err != nil {
		return err
	}
	return nil
}

// TODO(shibumi): we might want to export this function or add this to our package?!
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

// TODO(shibumi): we might want to export this function or add this to our package?!
func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}
