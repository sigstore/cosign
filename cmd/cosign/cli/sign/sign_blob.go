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

	manualTM, err := newTrustedMaterialFromKeyOpts(ko)
	if err != nil {
		return nil, fmt.Errorf("composing trusted material: %w", err)
	}

	if manualTM != nil {
		if ko.TrustedMaterial == nil {
			ko.TrustedMaterial = manualTM
		} else {
			ko.TrustedMaterial = root.TrustedMaterialCollection{manualTM, ko.TrustedMaterial}
		}
		ui.Infof(ctx, "Augmented trusted material from service flags")
	}

	if ko.TrustedMaterial == nil {
		fmt.Println("DEBUG: ko.TrustedMaterial is nil")
	} else {
		fmt.Println("DEBUG: ko.TrustedMaterial is NOT nil")
		r, err := json.MarshalIndent(ko.TrustedMaterial, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling trusted material: %w", err)
		}
		fmt.Println("DEBUG: ko.TrustedMaterial: ", string(r))
	}

	data, err := io.ReadAll(&payload)
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	content := &sign.PlainData{
		Data: data,
	}
	bundleBytes, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, ko.SigningConfig, ko.TrustedMaterial)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}

	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshalling bundle: %w", err)
	}
	
	sig, extractedCert, rekorEntry := extractElementsFromProtoBundle(&bundle)

	if ko.BundlePath != "" {
		var contents []byte
		if ko.NewBundleFormat {
			contents = bundleBytes
		} else {
			contents, err = newLegacyBundleFromProtoBundleElements(sig, extractedCert, rekorEntry)
			if err != nil {
				return nil, fmt.Errorf("creating legacy bundle: %w", err)
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

func extractElementsFromProtoBundle(bundle *protobundle.Bundle) ([]byte, *protocommon.X509Certificate, *protorekor.TransparencyLogEntry) {
	var extractedCert *protocommon.X509Certificate
	if bundle.VerificationMaterial.GetCertificate() != nil {
		extractedCert = bundle.VerificationMaterial.GetCertificate()
	}
	fmt.Println("DEBUG: extractedCert is ", extractedCert)
	var rekorEntry *protorekor.TransparencyLogEntry
	if len(bundle.VerificationMaterial.GetTlogEntries()) > 0 {
		rekorEntry = bundle.VerificationMaterial.GetTlogEntries()[0]
	}
	return bundle.GetMessageSignature().GetSignature(), extractedCert, rekorEntry
}

func newLegacyBundleFromProtoBundleElements(sig []byte, cert *protocommon.X509Certificate, rekorEntry *protorekor.TransparencyLogEntry) ([]byte, error) {
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
	} else {
		fmt.Println("DEBUG: cert is nil")
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

func newTrustedMaterialFromKeyOpts(ko options.KeyOpts) (root.TrustedMaterial, error) {
	var collection root.TrustedMaterialCollection

	if ko.TSAServerURL != "" && ko.TSACertChainPath != "" {
		tsaTM, err := buildTsaTrustedMaterial(ko.TSACertChainPath, ko.TSAServerURL)
		if err != nil {
			return nil, fmt.Errorf("building TSA trusted material: %w", err)
		}
		collection = append(collection, tsaTM)
	}

	if fulcioRootPath := env.Getenv(env.VariableSigstoreRootFile); fulcioRootPath != "" {
		fulcioTM, err := buildFulcioTrustedMaterial(fulcioRootPath, ko.FulcioURL)
		if err != nil {
			return nil, fmt.Errorf("building Fulcio trusted material: %w", err)
		}
		collection = append(collection, fulcioTM)
	}

	if ctLogKeyPath := env.Getenv(env.VariableSigstoreCTLogPublicKeyFile); ctLogKeyPath != "" {
		ctTM, err := buildCTLogTrustedMaterial(ctLogKeyPath)
		if err != nil {
			return nil, fmt.Errorf("building CT Log trusted material: %w", err)
		}
		collection = append(collection, ctTM)
	}

	if len(collection) == 0 {
		return nil, nil
	}

	return collection, nil
}

func buildTsaTrustedMaterial(chainPath, tsaURI string) (root.TrustedMaterial, error) {
	readCertsFromPEM := func(path string) ([]*x509.Certificate, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var certs []*x509.Certificate
		for {
			var block *pem.Block
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("no certificates found in %s", path)
		}
		return certs, nil
	}

	var leaf *x509.Certificate
	var intermediates []*x509.Certificate
	var rootCert *x509.Certificate

	if chainPath != "" {
		certs, err := readCertsFromPEM(chainPath)
		if err != nil {
			return nil, fmt.Errorf("reading chain file: %w", err)
		}
		chainLen := len(certs)
		if chainLen < 1 {
			return nil, fmt.Errorf("chain file %s contains no certs", chainPath)
		}
		for i, c := range certs {
			switch {
			case i == 0 && !c.IsCA:
				leaf = c
			case i < chainLen-1:
				intermediates = append(intermediates, c)
			case i == chainLen-1:
				rootCert = c
			}
		}
		if leaf == nil && len(certs) >= 1 && !certs[0].IsCA {
			leaf = certs[0]
		}
	}

	if rootCert == nil {
		return nil, fmt.Errorf("no root certificate available in TSA chain")
	}
	if leaf == nil {
		return nil, fmt.Errorf("no leaf certificate available in TSA chain")
	}

	tsa := &root.SigstoreTimestampingAuthority{
		Root:                rootCert,
		Intermediates:       intermediates,
		Leaf:                leaf,
		URI:                 tsaURI,
		ValidityPeriodStart: leaf.NotBefore,
		ValidityPeriodEnd:   leaf.NotAfter,
	}

	tm := &tsaMaterial{TSAs: []root.TimestampingAuthority{tsa}}
	return tm, nil
}

type tsaMaterial struct {
	root.BaseTrustedMaterial
	TSAs []root.TimestampingAuthority
}

func (t *tsaMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	return t.TSAs
}

func buildFulcioTrustedMaterial(rootPath, uri string) (root.TrustedMaterial, error) {
	certs, err := parseCerts(rootPath)
	if err != nil {
		return nil, fmt.Errorf("parsing Fulcio root certs: %w", err)
	}

	ca := &root.FulcioCertificateAuthority{
		Root:                certs[len(certs)-1],
		ValidityPeriodStart: certs[len(certs)-1].NotBefore,
		ValidityPeriodEnd:   certs[len(certs)-1].NotAfter,
		URI:                 uri,
	}
	if len(certs) > 1 {
		ca.Intermediates = certs[:len(certs)-1]
	}

	return &fulcioMaterial{fulcios: []root.CertificateAuthority{ca}}, nil
}

type fulcioMaterial struct {
	root.BaseTrustedMaterial
	fulcios []root.CertificateAuthority
}

func (f *fulcioMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return f.fulcios
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

func parseCerts(path string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for block, contents := pem.Decode(contents); block != nil; block, contents = pem.Decode(contents) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)

		if len(contents) == 0 {
			break
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in file %s", path)
	}

	return certs, nil
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
