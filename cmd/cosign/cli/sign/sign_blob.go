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
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	irekor "github.com/sigstore/cosign/internal/pkg/cosign/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	rekorClient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type KeyOpts struct {
	Sk               bool
	Slot             string
	KeyRef           string
	FulcioURL        string
	RekorURL         string
	IDToken          string
	PassFunc         cosign.PassFunc
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string

	// Modeled after InsecureSkipVerify in tls.Config, this disables
	// verifying the SCT.
	InsecureSkipFulcioVerify bool
}

// nolint
func SignBlobCmd(ctx context.Context, ko KeyOpts, regOpts options.RegistryOptions, payloadPath string, b64 bool, outputSignature string, outputCertificate string, timeout time.Duration) ([]byte, error) {
	var payload []byte
	var err error

	if payloadPath == "-" {
		payload, err = io.ReadAll(os.Stdin)
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = os.ReadFile(filepath.Clean(payloadPath))
	}
	if err != nil {
		return nil, err
	}
	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	signer, _, closeFn, err := SignerFromKeyOpts(ctx, "", ko)
	if err != nil {
		return nil, err
	}
	if closeFn != nil {
		defer closeFn()
	}

	if options.EnableExperimental() {
		rClient, err := rekorClient.GetRekorClient(ko.RekorURL)
		if err != nil {
			return nil, err
		}
		signer = irekor.NewSigner(signer, rClient)
	}

	ociSig, _, err := signer.Sign(ctx, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "signing blob")
	}

	b64Sig, err := ociSig.Base64Signature()
	if err != nil {
		return nil, errors.Wrap(err, "retrieving base64-encoded signature")
	}
	sigToOutput := []byte(b64Sig)
	if !b64 {
		sigToOutput, err = base64.StdEncoding.DecodeString(b64Sig)
		if err != nil {
			return nil, errors.Wrap(err, "base64-decoding signature")
		}
	}

	if outputSignature != "" {
		f, err := os.Create(outputSignature)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		_, err = f.Write(sigToOutput)
		if err != nil {
			return nil, err
		}

		fmt.Printf("Signature written to file: %s\n", f.Name())
	} else {
		if b64 {
			fmt.Println(string(sigToOutput))
		} else if _, err := os.Stdout.Write(sigToOutput); err != nil {
			// No newline if using the raw signature
			return nil, err
		}
	}

	if outputCertificate != "" {
		f, err := os.Create(outputCertificate)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		cert, err := ociSig.Cert()
		if err != nil {
			return nil, err
		}
		certBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}

		if b64 {
			certBytes = []byte(base64.StdEncoding.EncodeToString(certBytes))
		}
		_, err = f.Write(certBytes)
		if err != nil {
			return nil, err
		}
	}

	return sigToOutput, nil
}
