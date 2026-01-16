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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
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

	keypair, _, certBytes, idToken, err := signcommon.GetKeypairAndToken(ctx, ko, certPath, certChainPath)
	if err != nil {
		return nil, fmt.Errorf("getting keypair and token: %w", err)
	}

	hashFunction := protoHashAlgoToHash(keypair.GetHashAlgorithm())
	payload, closePayload, err := getPayload(ctx, payloadPath, hashFunction)
	if err != nil {
		return nil, fmt.Errorf("getting payload: %w", err)
	}
	defer closePayload()

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

	if ko.SigningConfig == nil {
		// TODO: Is this necessary? Or just enforce this in tests that call SignBlobCmd directly?
		// Default RekorVersion is set by flag, but e2e tests call SignBlobCmd directly
		if ko.RekorVersion == 0 {
			ko.RekorVersion = 1
		}
		ko.SigningConfig, err = newSigningConfigFromKeyOpts(ko, shouldUpload)
		if err != nil {
			return nil, fmt.Errorf("creating signing config: %w", err)
		}
	}

	data, err := io.ReadAll(&payload)
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	content := &sign.PlainData{
		Data: data,
	}
	certIdToken := idToken
	if len(certBytes) > 0 {
		certIdToken = ""
	}
	bundleBytes, err := cbundle.SignData(ctx, content, keypair, certIdToken, certBytes, ko.SigningConfig, ko.TrustedMaterial)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}

	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshalling bundle: %w", err)
	}

	sig, extractedCert, chains, rekorEntry, rfc3161Timestamp, err := extractElementsFromProtoBundle(&bundle)
	if err != nil {
		return nil, fmt.Errorf("extracting elements from bundle: %w", err)
	}

	var sctTrustedMaterial root.TrustedMaterial
	if ko.TrustedMaterial == nil {
		if ctLogKeyPath := env.Getenv(env.VariableSigstoreCTLogPublicKeyFile); ctLogKeyPath != "" {
			sctTrustedMaterial, err = buildCTLogTrustedMaterial(ctLogKeyPath)
		} else {
			sctTrustedMaterial, err = cosign.TrustedRoot()
		}
		if err != nil {
			ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF repository. Skipping client-side SCT verification. Error from TUF: %v", err)
		}
	}
	if sctTrustedMaterial != nil && !ko.InsecureSkipFulcioVerify && len(chains) > 0 {
		threshold := 0
		if ko.KeyRef == "" || ko.IssueCertificateForExistingKey {
			threshold = 1
		}
		if err := verify.VerifySignedCertificateTimestamp(chains, threshold, sctTrustedMaterial); err != nil {
			return nil, fmt.Errorf("verifying SCT: %w", err)
		}
		if threshold > 0 {
			ui.Infof(ctx, "SCT verified successfully")
		}
	}

	if ko.BundlePath != "" {
		var contents []byte
		if ko.NewBundleFormat {
			contents = bundleBytes
		} else {
			pubKeyPem, err := keypair.GetPublicKeyPem()
			if err != nil {
				return nil, fmt.Errorf("getting public key: %w", err)
			}
			block, _ := pem.Decode([]byte(pubKeyPem))
			if block == nil {
				return nil, fmt.Errorf("failed to decode public key pem")
			}
			contents, err = newLegacyBundleFromProtoBundleElements(sig, extractedCert, block.Bytes, rekorEntry)
			if err != nil {
				return nil, fmt.Errorf("creating legacy bundle: %w", err)
			}
			if rfc3161Timestamp != nil && ko.RFC3161TimestampPath != "" {
				legacyTimestamp := cbundle.TimestampToRFC3161Timestamp(rfc3161Timestamp.SignedTimestamp)
				ts, err := json.Marshal(legacyTimestamp)
				if err != nil {
					return nil, fmt.Errorf("marshalling timestamp: %w", err)
				}
				if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
					return nil, fmt.Errorf("create timestamp file: %w", err)
    		}
			}
		}

		if err := os.WriteFile(ko.BundlePath, contents, 0600); err != nil {
			return nil, fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	}

	if outputSignature != "" {
		bts := sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
		}
		if err := os.WriteFile(outputSignature, bts, 0600); err != nil {
			return nil, fmt.Errorf("create signature file: %w", err)
		}
		ui.Infof(ctx, "Wrote signature to file %s", outputSignature)
	} else {
		bts := sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
			fmt.Println(string(bts))
		} else {
			if _, err := os.Stdout.Write(bts); err != nil {
				return nil, err
			}
		}
	}

	if outputCertificate != "" && extractedCert != nil {
		bts := extractedCert.GetRawBytes()
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: extractedCert.GetRawBytes(),
		}
		certPem := pem.EncodeToMemory(pemBlock)
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(certPem))
		} else {
			bts = certPem
		}
		if err := os.WriteFile(outputCertificate, bts, 0600); err != nil {
			return nil, fmt.Errorf("create certificate file: %w", err)
		}
		ui.Infof(ctx, "Wrote certificate to file %s", outputCertificate)
	}

	if b64 {
		return []byte(base64.StdEncoding.EncodeToString(sig)), nil
	}
	return sig, nil
}

func newSigningConfigFromKeyOpts(ko options.KeyOpts, shouldUpload bool) (*root.SigningConfig, error) {
	var fulcioServices []root.Service
	if ko.FulcioURL != "" {
		fulcioServices = append(fulcioServices, root.Service{
			URL:                 ko.FulcioURL,
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now(),
		})
	}

	var rekorServices []root.Service
	var rekorConfig root.ServiceConfiguration
	if ko.RekorURL != "" && shouldUpload {
		rekorServices = append(rekorServices, root.Service{
			URL:                 ko.RekorURL,
			MajorAPIVersion:     ko.RekorVersion,
			ValidityPeriodStart: time.Now(),
		})
		rekorConfig = root.ServiceConfiguration{
			Selector: prototrustroot.ServiceSelector_ANY,
			Count:    1,
		}
	}

	var tsaServices []root.Service
	var tsaConfig root.ServiceConfiguration
	if ko.TSAServerURL != "" {
		tsaServices = append(tsaServices, root.Service{
			URL:                 ko.TSAServerURL,
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now(),
		})
		tsaConfig = root.ServiceConfiguration{
			Selector: prototrustroot.ServiceSelector_ANY,
			Count:    1,
		}
	}

	return root.NewSigningConfig(
		root.SigningConfigMediaType02,
		fulcioServices,
		nil,
		rekorServices,
		rekorConfig,
		tsaServices,
		tsaConfig,
	)
}

func extractElementsFromProtoBundle(bundle *protobundle.Bundle) ([]byte, *protocommon.X509Certificate, [][]*x509.Certificate, *protorekor.TransparencyLogEntry, *protocommon.RFC3161SignedTimestamp, error) {
	var sig []byte
	if bundle.GetMessageSignature().GetSignature() != nil {
		sig = bundle.GetMessageSignature().GetSignature()
	}

	var extractedCert *protocommon.X509Certificate
	var chains [][]*x509.Certificate
	if chain := bundle.VerificationMaterial.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		certs := chain.GetCertificates()
		extractedCert = certs[0]
		var parsedChain []*x509.Certificate
		for _, cert := range certs {
			parsed, err := x509.ParseCertificate(cert.RawBytes)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("parsing certificate from bundle: %w", err)
			}
			parsedChain = append(parsedChain, parsed)
		}
		chains = append(chains, parsedChain)
	} else if cert := bundle.VerificationMaterial.GetCertificate(); cert != nil {
		extractedCert = cert
		parsed, err := x509.ParseCertificate(cert.RawBytes)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("parsing certificate from bundle: %w", err)
		}
		chains = append(chains, []*x509.Certificate{parsed})
	}

	var rekorEntry *protorekor.TransparencyLogEntry
	if len(bundle.VerificationMaterial.GetTlogEntries()) > 0 {
		rekorEntry = bundle.VerificationMaterial.GetTlogEntries()[0]
	}

	var timestamp *protocommon.RFC3161SignedTimestamp
	if bundle.GetVerificationMaterial().TimestampVerificationData.GetRfc3161Timestamps() != nil &&
		len(bundle.GetVerificationMaterial().TimestampVerificationData.GetRfc3161Timestamps()) > 0 {
		timestamp = bundle.GetVerificationMaterial().TimestampVerificationData.GetRfc3161Timestamps()[0]
	}

	return sig, extractedCert, chains, rekorEntry, timestamp, nil
}

func newLegacyBundleFromProtoBundleElements(sig []byte, cert *protocommon.X509Certificate, pubKey []byte, rekorEntry *protorekor.TransparencyLogEntry) ([]byte, error) {
	signedPayload := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
	}
	if cert != nil {
		fmt.Println("DEBUG: cert is NOT nil")
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.GetRawBytes(),
		}
		certPem := pem.EncodeToMemory(pemBlock)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(certPem)
	} else if len(pubKey) > 0 {
		fmt.Println("DEBUG: using public key fallback for legacy bundle")
		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKey,
		}
		pubPem := pem.EncodeToMemory(pemBlock)
		signedPayload.Cert = base64.StdEncoding.EncodeToString(pubPem)
	} else {
		fmt.Println("DEBUG: cert and pubKey are nil")
	}
	if rekorEntry != nil {
		signedPayload.Bundle = &cbundle.RekorBundle{
			SignedEntryTimestamp: rekorEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
			Payload: cbundle.RekorPayload{
				Body:           rekorEntry.GetCanonicalizedBody(),
				IntegratedTime: rekorEntry.GetIntegratedTime(),
				LogIndex:       rekorEntry.GetLogIndex(),
				LogID:          hex.EncodeToString(rekorEntry.GetLogId().GetKeyId()),
			},
		}
	}
	return json.Marshal(signedPayload)
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

func buildCTLogTrustedMaterial(keyPath string) (root.TrustedMaterial, error) {
	pubKey, id, idBytes, err := getPubKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("parsing CT Log public key: %w", err)
	}

	tlog := &root.TransparencyLog{
		HashFunc:            crypto.SHA256,
		ID:                  idBytes,
		ValidityPeriodStart: time.Unix(0, 0),
		PublicKey:           pubKey,
		SignatureHashFunc:   getSignatureHashAlgo(pubKey),
	}

	return &ctLogMaterial{ctlogs: map[string]*root.TransparencyLog{id: tlog}}, nil
}

type ctLogMaterial struct {
	root.BaseTrustedMaterial
	ctlogs map[string]*root.TransparencyLog
}

func (c *ctLogMaterial) CTLogs() map[string]*root.TransparencyLog {
	return c.ctlogs
}

func getPubKey(path string) (crypto.PublicKey, string, []byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", []byte{}, err
	}

	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, "", []byte{}, err
	}

	keyID, err := cosign.GetTransparencyLogID(pubKey)
	if err != nil {
		return nil, "", []byte{}, err
	}

	idBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return nil, "", []byte{}, err
	}

	return pubKey, keyID, idBytes, nil
}

func getSignatureHashAlgo(pubKey crypto.PublicKey) crypto.Hash {
	var h crypto.Hash
	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		h = crypto.SHA256
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		default:
			h = crypto.SHA256
		}
	case ed25519.PublicKey:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	return h
}
