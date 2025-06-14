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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	internal "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func SignBlobCmd(ro *options.RootOptions, ko options.KeyOpts, payloadPath string, b64 bool, outputSignature string, outputCertificate string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader

	ctx, cancel := context.WithTimeout(context.Background(), ro.Timeout)
	defer cancel()

	if payloadPath == "-" {
		payload = internal.NewHashReader(os.Stdin, sha256.New())
	} else {
		ui.Infof(ctx, "Using payload from: %s", payloadPath)
		f, err := os.Open(filepath.Clean(payloadPath))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		payload = internal.NewHashReader(f, sha256.New())
	}

	sv, err := SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return nil, err
	}
	defer sv.Close()

	sig, err := sv.SignMessage(&payload, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing blob: %w", err)
	}
	digest := payload.Sum(nil)

	signedPayload := cosign.LocalSignedPayload{}
	var rekorEntry *models.LogEntryAnon
	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	var timestampBytes []byte

	if ko.TSAServerURL != "" {
		if ko.RFC3161TimestampPath == "" && !ko.NewBundleFormat {
			return nil, fmt.Errorf("must use protobuf bundle or set timestamp output path")
		}
		var err error
		if ko.TSAClientCACert == "" && ko.TSAClientCert == "" { // no mTLS params or custom CA
			timestampBytes, err = tsa.GetTimestampedSignature(sig, client.NewTSAClient(ko.TSAServerURL))
			if err != nil {
				return nil, err
			}
		} else {
			timestampBytes, err = tsa.GetTimestampedSignature(sig, client.NewTSAClientMTLS(ko.TSAServerURL,
				ko.TSAClientCACert,
				ko.TSAClientCert,
				ko.TSAClientKey,
				ko.TSAServerName,
			))
			if err != nil {
				return nil, err
			}
		}

		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(timestampBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return nil, fmt.Errorf("rfc3161 timestamp is nil")
		}

		if ko.RFC3161TimestampPath != "" {
			ts, err := json.Marshal(rfc3161Timestamp)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
				return nil, fmt.Errorf("create RFC3161 timestamp file: %w", err)
			}
			ui.Infof(ctx, "RFC3161 timestamp written to file %s\n", ko.RFC3161TimestampPath)
		}
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
		rekorEntry, err = cosign.TLogUpload(ctx, rekorClient, sig, &payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		ui.Infof(ctx, "tlog entry created with index: %d", *rekorEntry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(rekorEntry)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		var contents []byte
		if ko.NewBundleFormat {
			// Determine if signature is certificate or not
			var hint string
			var rawCert []byte

			signer, err := sv.Bytes(ctx)
			if err != nil {
				return nil, fmt.Errorf("error getting signer: %w", err)
			}
			cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
			if err != nil || len(cert) == 0 {
				pubKey, err := sv.PublicKey()
				if err != nil {
					return nil, err
				}
				pkixPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
				hashedBytes := sha256.Sum256(pkixPubKey)
				hint = base64.StdEncoding.EncodeToString(hashedBytes[:])
			} else {
				rawCert = cert[0].Raw
			}

			bundle, err := cbundle.MakeProtobufBundle(hint, rawCert, rekorEntry, timestampBytes)
			if err != nil {
				return nil, err
			}

			bundle.Content = &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{
					MessageDigest: &protocommon.HashOutput{
						Algorithm: protocommon.HashAlgorithm_SHA2_256,
						Digest:    digest,
					},
					Signature: sig,
				},
			}

			contents, err = protojson.Marshal(bundle)
			if err != nil {
				return nil, err
			}
		} else {
			signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)

			certBytes, err := extractCertificate(ctx, sv)
			if err != nil {
				return nil, err
			}
			signedPayload.Cert = base64.StdEncoding.EncodeToString(certBytes)

			contents, err = json.Marshal(signedPayload)
			if err != nil {
				return nil, err
			}
		}

		if err := os.WriteFile(ko.BundlePath, contents, 0600); err != nil {
			return nil, fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	}

	if outputSignature != "" {
		var bts = sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
		}
		if err := os.WriteFile(outputSignature, bts, 0600); err != nil {
			return nil, fmt.Errorf("create signature file: %w", err)
		}
		ui.Infof(ctx, "Wrote signature to file %s", outputSignature)
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
			ui.Infof(ctx, "Wrote certificate to file %s", outputCertificate)
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
