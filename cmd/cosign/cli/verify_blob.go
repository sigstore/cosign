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
	"crypto"
	"crypto/ecdsa"
	_ "crypto/sha256" // for `crypto.SHA256`
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func VerifyBlob() *ffcli.Command {
	var (
		flagset   = flag.NewFlagSet("cosign verify-blob", flag.ExitOnError)
		key       = flagset.String("key", "", "path to the public key file, URL, or KMS URI")
		sk        = flagset.Bool("sk", false, "whether to use a hardware security key")
		slot      = flagset.String("slot", "", "security key slot to use for generated key (default: signature) (authentication|signature|card-authentication|key-management)")
		rekorURL  = flagset.String("rekor-url", "https://rekor.sigstore.dev", "[EXPERIMENTAL] address of rekor STL server")
		cert      = flagset.String("cert", "", "path to the public certificate")
		signature = flagset.String("signature", "", "signature content or path or remote URL")
		regOpts   RegistryOpts
	)
	ApplyRegistryFlags(&regOpts, flagset)
	return &ffcli.Command{
		Name:       "verify-blob",
		ShortUsage: "cosign verify-blob (-key <key path>|<key url>|<kms uri>)|(-cert <cert>) -signature <sig> <blob>",
		ShortHelp:  "Verify a signature on the supplied blob",
		LongHelp: `Verify a signature on the supplied blob input using the specified key reference.
You may specify either a key, a certificate or a kms reference to verify against.
	If you use a key or a certificate, you must specify the path to them on disk.

The signature may be specified as a path to a file or a base64 encoded string.
The blob may be specified as a path to a file or - for stdin.

EXAMPLES
  # Verify a simple blob and message
  cosign verify-blob -key cosign.pub -signature sig msg

  # Verify a simple blob with remote signature URL, both http and https schemes are supported
  cosign verify-blob -key cosign.pub -signature http://host/my.sig

  # Verify a signature from an environment variable
  cosign verify-blob -key cosign.pub -signature $sig msg

  # verify a signature with public key provided by URL
  cosign verify-blob -key https://host.for/<FILE> -signature $sig msg

  # Verify a signature against a payload from another process using process redirection
  cosign verify-blob -key cosign.pub -signature $sig <(git rev-parse HEAD)

  # Verify a signature against Azure Key Vault
  cosign verify-blob -key azurekms://[VAULT_NAME][VAULT_URI]/[KEY] -signature $sig <blob>

  # Verify a signature against AWS KMS
  cosign verify-blob -key awskms://[ENDPOINT]/[ID/ALIAS/ARN] -signature $sig <blob>

  # Verify a signature against Google Cloud KMS
  cosign verify-blob -key gcpkms://projects/[PROJECT ID]/locations/[LOCATION]/keyRings/[KEYRING]/cryptoKeys/[KEY] -signature $sig <blob>

  # Verify a signature against Hashicorp Vault
  cosign verify-blob -key hashivault://[KEY] -signature $sig <blob>`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return flag.ErrHelp
			}
			ko := KeyOpts{
				KeyRef:   *key,
				Sk:       *sk,
				RekorURL: *rekorURL,
				Slot:     *slot,
			}
			if err := VerifyBlobCmd(ctx, ko, *cert, *signature, args[0]); err != nil {
				return errors.Wrapf(err, "verifying blob %s", args)
			}
			return nil
		},
	}
}

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

func VerifyBlobCmd(ctx context.Context, ko KeyOpts, certRef, sigRef, blobRef string) error {
	var pubKey signature.Verifier
	var err error
	var cert *x509.Certificate

	if !oneOf(ko.KeyRef, ko.Sk, certRef) {
		return &KeyParseError{}
	}

	// Keys are optional!
	switch {
	case ko.KeyRef != "":
		pubKey, err = publicKeyFromKeyRef(ctx, ko.KeyRef)
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
		pems, err := ioutil.ReadFile(certRef)
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
		pubKey, err = signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return err
		}
	}

	var b64sig string
	targetSig, err := loadFileOrURL(sigRef)
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
		blobBytes, err = ioutil.ReadAll(os.Stdin)
	} else {
		blobBytes, err = loadFileOrURL(blobRef)
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

	if EnableExperimental() {
		rekorClient, err := rekorClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return err
		}
		var pubBytes []byte
		if pubKey != nil {
			pubBytes, err = publicKeyPem(pubKey, options.WithContext(ctx))
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
