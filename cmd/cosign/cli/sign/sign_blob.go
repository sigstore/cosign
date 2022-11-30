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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/internal/pkg/cosign/tsa"
	cbundle "github.com/sigstore/cosign/pkg/cosign/bundle"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"

	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	internal "github.com/sigstore/cosign/internal/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func SignBlobCmd(ro *options.RootOptions, ko options.KeyOpts, payloadPath string, b64 bool, outputSignature string, outputCertificate string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader
	var err error
	var rekorBytes []byte

	if payloadPath == "-" {
		payload = internal.NewHashReader(os.Stdin, sha256.New())
	} else {
		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		f, err := os.Open(filepath.Clean(payloadPath))
		if err != nil {
			return nil, err
		}
		payload = internal.NewHashReader(f, sha256.New())
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

	sig, err := sv.SignMessage(&payload, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing blob: %w", err)
	}

	signedPayload := cosign.LocalSignedPayload{}

	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	if ko.TSAServerURL != "" {
		clientTSA, err := tsaclient.GetTimestampClient(ko.TSAServerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create TSA client: %w", err)
		}

		respBytes, err := tsa.GetTimestampedSignature(sig, clientTSA)
		if err != nil {
			return nil, err
		}

		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(respBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor
	}
	if ShouldUploadToTlog(ctx, ko, nil, tlogUpload) {
		rekorBytes, err = sv.Bytes(ctx)
		if err != nil {
			return nil, err
		}
		rekorClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return nil, err
		}
		entry, err := cosign.TLogUpload(ctx, rekorClient, sig, &payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(entry)
	}

	if ko.RFC3161TimestampPath != "" && rfc3161Timestamp != nil {
		ts, err := json.Marshal(rfc3161Timestamp)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
			return nil, fmt.Errorf("create rfc3161 timestamp file: %w", err)
		}
		fmt.Printf("RFC3161 timestamp bundle written to file %s\n", ko.RFC3161TimestampPath)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(rekorBytes)

		contents, err := json.Marshal(signedPayload)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(ko.BundlePath, contents, 0600); err != nil {
			return nil, fmt.Errorf("create bundle file: %w", err)
		}
		fmt.Printf("Bundle wrote in the file %s\n", ko.BundlePath)
	}

	if outputSignature != "" {
		var bts = sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
		}
		if err := os.WriteFile(outputSignature, bts, 0600); err != nil {
			return nil, fmt.Errorf("create signature file: %w", err)
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

	if outputCertificate != "" {
		signer, err := sv.Bytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting signer: %w", err)
		}
		cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
		// signer is a certificate
		if err == nil && len(cert) == 1 {
			bts := signer
			if b64 {
				bts = []byte(base64.StdEncoding.EncodeToString(signer))
			}
			if err := os.WriteFile(outputCertificate, bts, 0600); err != nil {
				return nil, fmt.Errorf("create certificate file: %w", err)
			}
			fmt.Printf("Certificate wrote in the file %s\n", outputCertificate)
		}
	}

	return sig, nil
}
