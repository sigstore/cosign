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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
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
	OIDCRedirectURI  string
	BundlePath       string

	// Modeled after InsecureSkipVerify in tls.Config, this disables
	// verifying the SCT.
	InsecureSkipFulcioVerify bool
}

// nolint
func SignBlobCmd(ro *options.RootOptions, ko KeyOpts, regOpts options.RegistryOptions, payloadPath string, b64 bool, outputSignature string, outputCertificate string) ([]byte, error) {
	var payload []byte
	var err error
	var rekorBytes []byte

	if payloadPath == "-" {
		payload, err = io.ReadAll(os.Stdin)
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = os.ReadFile(filepath.Clean(payloadPath))
	}
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), ro.Timeout)
	defer cancel()

	sv, err := SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return nil, err
	}
	defer sv.Close()

	sig, err := sv.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "signing blob")
	}

	signedPayload := cosign.LocalSignedPayload{}

	if options.EnableExperimental() {
		rekorBytes, err = sv.Bytes(ctx)
		if err != nil {
			return nil, err
		}
		rekorClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return nil, err
		}
		entry, err := cosign.TLogUpload(ctx, rekorClient, sig, payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(entry)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(rekorBytes)

		contents, err := json.Marshal(signedPayload)
		if err != nil {
			return nil, err
		}
		return []byte(signedPayload.Base64Signature), os.WriteFile(ko.BundlePath, contents, 0600)
	}

	if outputSignature != "" {
		var bts = sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
		}
		if err := os.WriteFile(outputSignature, bts, 0600); err != nil {
			return nil, errors.Wrap(err, "create signature file")
		}

		fmt.Printf("Signature wrote in the file %s\n", outputSignature)
	} else {
		if b64 {
			sig = []byte(base64.StdEncoding.EncodeToString(sig))
			fmt.Println(string(sig))
		} else if _, err := os.Stdout.Write(sig); err != nil {
			// No newline if using the raw signature
			return nil, err
		}
	}

	if outputCertificate != "" && len(rekorBytes) > 0 {
		bts := rekorBytes
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(rekorBytes))
		}
		if err := os.WriteFile(outputCertificate, bts, 0600); err != nil {
			return nil, errors.Wrap(err, "create certificate file")
		}
		fmt.Printf("Certificate wrote in the file %s\n", outputCertificate)
	}

	return sig, nil
}
