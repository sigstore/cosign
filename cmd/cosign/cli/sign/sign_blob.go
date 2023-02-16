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

	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	internal "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func SignBlobCmd(ro *options.RootOptions, ko options.KeyOpts, payloadPath string, b64 bool, outputSignature string, outputCertificate string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader
	var err error

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
		if ko.RFC3161TimestampPath == "" {
			return nil, fmt.Errorf("timestamp output path must be set")
		}

		respBytes, err := tsa.GetTimestampedSignature(sig, client.NewTSAClient(ko.TSAServerURL))
		if err != nil {
			return nil, err
		}

		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(respBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return nil, fmt.Errorf("rfc3161 timestamp is nil")
		}
		ts, err := json.Marshal(rfc3161Timestamp)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
			return nil, fmt.Errorf("create RFC3161 timestamp file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "RFC3161 timestamp written to file %s\n", ko.RFC3161TimestampPath)
	}
	shouldUpload, err := ShouldUploadToTlog(ctx, ko, nil, tlogUpload)
	if err != nil {
		return nil, fmt.Errorf("upload to tlog: %w", err)
	}
	if shouldUpload {
		rekorBytes, err := sv.Bytes(ctx)
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

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)

		certBytes, err := extractCertificate(ctx, sv)
		if err != nil {
			return nil, err
		}
		signedPayload.Cert = base64.StdEncoding.EncodeToString(certBytes)

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
		certBytes, err := extractCertificate(ctx, sv)
		if err != nil {
			return nil, err
		}
		if certBytes != nil {
			bts := certBytes
			if b64 {
				bts = []byte(base64.StdEncoding.EncodeToString(certBytes))
			}
			if err := os.WriteFile(outputCertificate, bts, 0600); err != nil {
				return nil, fmt.Errorf("create certificate file: %w", err)
			}
			fmt.Printf("Certificate wrote in the file %s\n", outputCertificate)
		}
	}

	return sig, nil
}

// Extract an encoded certificate from the SignerVerifier. Returns (nil, nil) if verifier is not a certificate.
func extractCertificate(ctx context.Context, sv *SignerVerifier) ([]byte, error) {
	signer, err := sv.Bytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting signer: %w", err)
	}
	cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
	// signer is a certificate
	if err == nil && len(cert) == 1 {
		return signer, nil
	}
	return nil, nil
}
