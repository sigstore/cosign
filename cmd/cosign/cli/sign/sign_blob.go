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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func getPayload(ctx context.Context, payloadPath string, hashFunction crypto.Hash) (internal.HashReader, func() error, error) {
	if payloadPath == "-" {
		return internal.NewHashReader(os.Stdin, hashFunction), func() error { return nil }, nil
	}
	ui.Infof(ctx, "Using payload from: %s", payloadPath)
	f, err := os.Open(filepath.Clean(payloadPath))
	if err != nil {
		return internal.HashReader{}, nil, err
	}
	return internal.NewHashReader(f, hashFunction), f.Close, nil
}

// nolint
func SignBlobCmd(ctx context.Context, ro *options.RootOptions, ko options.KeyOpts, payloadPath, certPath, certChainPath string, b64 bool, outputSignature string, outputCertificate string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader

	ctx, cancel := context.WithTimeout(ctx, ro.Timeout)
	defer cancel()

	// TODO - this does not take ko.SigningConfig into account
	if !tlogUpload {
		// To maintain backwards compatibility with older cosign versions,
		// we do not use ed25519ph for ed25519 keys when the signatures are not
		// uploaded to the Tlog.
		ko.DefaultLoadOptions = &[]signature.LoadOption{}
	}

	keypair, sv, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, certPath, certChainPath)
	if err != nil {
		return nil, fmt.Errorf("getting keypair and token: %w", err)
	}

	hashFunction := protoHashAlgoToHash(keypair.GetHashAlgorithm())
	payload, closePayload, err := getPayload(ctx, payloadPath, hashFunction)
	if err != nil {
		return nil, fmt.Errorf("getting payload: %w", err)
	}
	defer closePayload()

	if ko.SigningConfig != nil {
		data, err := io.ReadAll(&payload)
		if err != nil {
			return nil, fmt.Errorf("reading payload: %w", err)
		}
		content := &sign.PlainData{
			Data: data,
		}
		bundle, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, ko.SigningConfig, ko.TrustedMaterial)
		if err != nil {
			return nil, fmt.Errorf("signing bundle: %w", err)
		}
		if err := os.WriteFile(ko.BundlePath, bundle, 0600); err != nil {
			return nil, fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
		return bundle, nil
	}

	shouldUpload, err := signcommon.ShouldUploadToTlog(ctx, ko, nil, tlogUpload)
	if err != nil {
		return nil, fmt.Errorf("upload to tlog: %w", err)
	}

	if hashFunction != crypto.SHA256 && !ko.NewBundleFormat && (shouldUpload || (!ko.Sk && ko.KeyRef == "")) {
		ui.Infof(ctx, "Non SHA256 hash function is not supported for old bundle format. Use --new-bundle-format to use the new bundle format or use different signing key/algorithm.")
		if !ko.SkipConfirmation {
			if err := ui.ConfirmContinue(ctx); err != nil {
				return nil, err
			}
		}
		ui.Infof(ctx, "Continuing with non SHA256 hash function and old bundle format")
	}

	sig, err := sv.SignMessage(&payload, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing blob: %w", err)
	}
	digest := payload.Sum(nil)

	signedPayload := cosign.LocalSignedPayload{}

	timestampBytes, _, err := signcommon.GetRFC3161Timestamp(sig, ko)
	if err != nil {
		return nil, fmt.Errorf("getting timestamp: %w", err)
	}

	signer, err := sv.Bytes(ctx)
	if err != nil {
		return nil, err
	}
	rekorEntry, err := signcommon.UploadToTlog(ctx, ko, nil, shouldUpload, signer, func(r *rekorclient.Rekor, b []byte) (*models.LogEntryAnon, error) {
		return cosign.TLogUploadWithCustomHash(ctx, r, sig, &payload, b)
	})
	if err != nil {
		return nil, err
	}
	if rekorEntry != nil {
		signedPayload.Bundle = cbundle.EntryToBundle(rekorEntry)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		var contents []byte
		if ko.NewBundleFormat {
			// Determine if signature is certificate or not
			var hint string
			var rawCert []byte

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
						Algorithm: hashFuncToProtoBundle(payload.HashFunc()),
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
func extractCertificate(ctx context.Context, sv *signcommon.SignerVerifier) ([]byte, error) {
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

func hashFuncToProtoBundle(hashFunc crypto.Hash) protocommon.HashAlgorithm {
	switch hashFunc {
	case crypto.SHA256:
		return protocommon.HashAlgorithm_SHA2_256
	case crypto.SHA384:
		return protocommon.HashAlgorithm_SHA2_384
	case crypto.SHA512:
		return protocommon.HashAlgorithm_SHA2_512
	default:
		return protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	}
}

func protoHashAlgoToHash(hashFunc protocommon.HashAlgorithm) crypto.Hash {
	switch hashFunc {
	case protocommon.HashAlgorithm_SHA2_256:
		return crypto.SHA256
	case protocommon.HashAlgorithm_SHA2_384:
		return crypto.SHA384
	case protocommon.HashAlgorithm_SHA2_512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
